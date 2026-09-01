//! Agent-mode startup wiring: settings-gated proxy plus feature.
//!
//! Compiled in only behind the `agent-mode` Cargo feature (off by default,
//! same posture as `automation`); even then, nothing listens
//! unless the user has turned the interface on via the editable
//! `conman.ini` document (`automation-enabled`,
//! off by default). See [`proxy`] for the
//! actual scope-enforcement engine.
//!
//! ## Startup
//! 1. [`prepare`] — called from `main` **before** `logging::init`, in the
//!    same environment-safe window `render_backend::resolve` relies on for
//!    its own `unsafe std::env::set_var`. If automation is enabled, this binds
//!    the user-facing (external) loopback listener immediately, picks a port
//!    for the internal vendored Slint MCP server, and sets `SLINT_MCP_PORT`
//!    to that internal port — which must happen before the Slint backend
//!    initializes (i.e. before any window is shown), trivially true this
//!    early in `main`. Returns `None` (no env var touched, nothing bound) if
//!    automation is disabled or the settings/port allocation can't be read.
//! 2. [`spawn`] — called later (anywhere after `logging::init`; thread
//!    spawns are unrestricted from then on), takes the [`Prepared`] value
//!    [`prepare`] returned and starts the accept-loop thread.
//!
//! ## UI integration
//! [`spawn`] returns an [`AgentModeHandle`] carrying the external port and an
//! `Arc<RwLock<ScopeSet>>` the Settings UI's live scope-reload writes into
//! `main.rs` mirrors the
//! cm-ui-relevant fields into `cm_ui::AgentModeConfig` (`cm-ui` cannot depend
//! on `conman` directly - the dependency points the other way) and threads
//! it into `AppConfig` (the same injection pattern already used for
//! `secrets`/`session_provider`), so the Settings section can (a) display
//! the listening port + loopback host, (b) show the persistent active
//! indicator, and (c) write a new `ScopeSet` into the handle's lock when the
//! user changes a scope checkbox. Turning `automation-enabled` off at
//! runtime does **not** stop an already-running listener this session (only
//! scope changes are live-reloadable) — full disable takes effect on next
//! launch.

mod proxy;

use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};

use cm_core::{AppConfigStore, ScopeSet, SettingsService};

/// The result of [`prepare`]: an already-bound external listener plus
/// everything [`spawn`] needs to start serving it. Threaded through `main`
/// across the `logging::init` call.
pub(crate) struct Prepared {
    external_listener: TcpListener,
    internal_port: u16,
    scopes: ScopeSet,
}

/// Returned by [`spawn`] with the listener state used by the UI.
pub(crate) struct AgentModeHandle {
    pub(crate) external_port: u16,
    #[allow(dead_code)] // only used for the startup log line above; not surfaced to cm-ui
    pub(crate) internal_port: u16,
    pub(crate) scopes: Arc<RwLock<ScopeSet>>,
    /// Mirrors 1:1 into
    /// `cm_ui::AgentModeConfig::mcp_interaction_count` - see that field's
    /// doc comment for the full "why a counter, not a bool" + timing-proof
    /// rationale. `proxy::run` increments/decrements the SAME `Arc` around
    /// every forwarded write-scoped `tools/call`.
    pub(crate) mcp_interaction_count: Arc<AtomicUsize>,
}

/// Binds the external (agent-facing) loopback listener and picks an internal
/// port for the vendored Slint MCP server, **if and only if**
/// `automation-enabled` is set. Must be called before `logging::init` —
/// see the module doc.
///
/// # Safety / ordering invariant
/// Setting `SLINT_MCP_PORT` uses `std::env::set_var`, which is `unsafe`
/// because it races with any other thread reading the environment. This
/// function is only ever called from `main`, before `logging::init`
/// (which, in release builds, spawns a background log-appender thread) and
/// before unrestricted workers. The sole concurrent worker is the audited
/// single-instance responder, which performs only socket I/O, tracing, and
/// mpsc sends and never accesses the environment. This is exactly the
/// invariant `render_backend::force_software_backend` documents for
/// `SLINT_BACKEND`. Do not call this after other workers are allowed to start.
pub(crate) fn prepare(config_store: &dyn AppConfigStore) -> Option<Prepared> {
    let automation = match SettingsService::new(config_store).load_automation() {
        Ok(settings) => settings,
        Err(error) => {
            // No subscriber exists yet. Fail closed: malformed or unreadable
            // configuration must never enable the listener accidentally.
            write_pre_logging_error(format_args!(
                "agent-mode: could not read automation configuration: {error}"
            ));
            return None;
        }
    };
    if !automation.enabled {
        return None;
    }

    let external_listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            // No tracing subscriber yet (this runs before `logging::init`)
            // stderr is the only option, matching main.rs's other
            // pre-logging fatal-adjacent messages.
            write_pre_logging_error(format_args!(
                "agent-mode: failed to bind the external loopback listener: {e}"
            ));
            return None;
        }
    };

    // Pick a free port for the internal vendored server by binding a
    // throwaway listener to port 0, reading the OS-assigned port, then
    // dropping it immediately so the Slint backend can bind it in turn.
    // This has an inherent (tiny, loopback-only, single-user-dev-machine)
    // TOCTOU window between the drop and the Slint backend's own bind -
    // accepted for v1, same trade-off every "hand a free port to a
    // subprocess/library I don't control the binding of" tool makes.
    let internal_port = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(probe) => match probe.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => {
                write_pre_logging_error(format_args!(
                    "agent-mode: failed to read a free internal port: {e}"
                ));
                return None;
            }
        },
        Err(e) => {
            write_pre_logging_error(format_args!(
                "agent-mode: failed to allocate an internal port: {e}"
            ));
            return None;
        }
    };

    #[allow(unsafe_code)] // see this function's doc comment for the upheld invariant
    unsafe {
        std::env::set_var("SLINT_MCP_PORT", internal_port.to_string());
    }

    Some(Prepared {
        external_listener,
        internal_port,
        scopes: automation.scopes,
    })
}

fn write_pre_logging_error(message: std::fmt::Arguments<'_>) {
    let safe = cm_cli::neutralize_terminal_text(&message.to_string());
    let _ = cm_platform::write_stderr_line(&safe);
}

/// Starts the proxy's accept-loop thread. Safe to call any time after
/// `logging::init`. Returns the handle described in the module doc.
pub(crate) fn spawn(prepared: Prepared) -> AgentModeHandle {
    let Prepared {
        external_listener,
        internal_port,
        scopes,
    } = prepared;
    let external_port = external_listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(0);
    let scopes = Arc::new(RwLock::new(scopes));
    let mcp_interaction_count = Arc::new(AtomicUsize::new(0));

    tracing::info!(
        external_port,
        internal_port,
        "agent-mode: scope-enforcement proxy listening (loopback only)"
    );

    let scopes_for_thread = Arc::clone(&scopes);
    let count_for_thread = Arc::clone(&mcp_interaction_count);
    std::thread::spawn(move || {
        proxy::run(
            external_listener,
            internal_port,
            scopes_for_thread,
            count_for_thread,
        )
    });

    AgentModeHandle {
        external_port,
        internal_port,
        scopes,
        mcp_interaction_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::AppConfigError;

    struct EmptyConfig;

    impl AppConfigStore for EmptyConfig {
        fn get_value(&self, _key: &str) -> Result<Option<String>, AppConfigError> {
            Ok(None)
        }

        fn set_value(&self, _key: &str, _value: &str) -> Result<(), AppConfigError> {
            unreachable!("agent-mode preparation only reads configuration")
        }

        fn set_values(&self, _values: &[(&str, &str)]) -> Result<(), AppConfigError> {
            unreachable!("agent-mode preparation only reads configuration")
        }

        fn document_text(&self) -> Result<String, AppConfigError> {
            Ok(String::new())
        }

        fn replace_document(&self, _document: &str) -> Result<(), AppConfigError> {
            unreachable!("agent-mode preparation only reads configuration")
        }
    }

    #[test]
    fn disabled_default_does_not_prepare_a_listener() {
        assert!(prepare(&EmptyConfig).is_none());
    }
}
