//! P8.6-A — agent-mode startup wiring: settings-gated proxy + feature.
//!
//! Compiled in only behind the `agent-mode` Cargo feature (off by default,
//! same posture as `qa-harness`/`automation`); even then, nothing listens
//! unless the user has turned the interface on via
//! `cm_core::SettingsService::load_automation` (`automation.enabled`,
//! off by default — the product's decided consent model, see
//! `docs/devel/tasks/P8.6-agentic-product-slice.md`). See [`proxy`] for the
//! actual scope-enforcement engine.
//!
//! ## Two-phase startup (mirrors `render_backend`'s split)
//! 1. [`prepare`] — called from `main` **before** `logging::init()`, in the
//!    same single-threaded window `render_backend::resolve` relies on for its
//!    own `unsafe std::env::set_var`. If automation is enabled, this binds
//!    the user-facing (external) loopback listener immediately, picks a port
//!    for the internal vendored Slint MCP server, and sets `SLINT_MCP_PORT`
//!    to that internal port — which must happen before the Slint backend
//!    initializes (i.e. before any window is shown), trivially true this
//!    early in `main`. Returns `None` (no env var touched, nothing bound) if
//!    automation is disabled or the settings/port allocation can't be read.
//! 2. [`spawn`] — called later (anywhere after `logging::init()`; thread
//!    spawns are unrestricted from then on), takes the [`Prepared`] value
//!    [`prepare`] returned and starts the accept-loop thread.
//!
//! ## The P8.6-B seam (not wired yet — noted for ui-dev)
//! [`spawn`] returns an [`AgentModeHandle`] carrying the external/internal
//! ports and an `Arc<RwLock<ScopeSet>>` the Settings UI's live scope-reload
//! is meant to write into (P8.6-impl.md's "Reload behavior"). `main.rs`
//! currently just holds this value without threading it anywhere — `cm-ui`
//! cannot reach back into `conman` (the dependency points the other way), so
//! P8.6-B needs to add a slot for this handle to `cm_ui::AppConfig` (the
//! same injection pattern already used for `secrets`/`session_provider`) so
//! the Settings section can (a) display the listening port + loopback host,
//! (b) show the persistent active indicator, and (c) write a new `ScopeSet`
//! into the handle's lock when the user changes a scope checkbox. Turning
//! `automation.enabled` off at runtime does **not** stop an already-running
//! listener this session (only scope changes are live-reloadable per the
//! spec) — full disable takes effect on next launch; flagged for Fable/user
//! review alongside the rest of this design.

mod proxy;

use std::net::TcpListener;
use std::sync::{Arc, RwLock};

use cm_core::{ConnectionRepository, ScopeSet, SettingsService};

/// The result of [`prepare`]: an already-bound external listener plus
/// everything [`spawn`] needs to start serving it. Threaded through `main`
/// across the `logging::init()` call.
pub(crate) struct Prepared {
    external_listener: TcpListener,
    internal_port: u16,
    scopes: ScopeSet,
}

/// Returned by [`spawn`] — see the module doc's "P8.6-B seam" section for
/// what this is for.
pub(crate) struct AgentModeHandle {
    #[allow(dead_code)] // consumed by P8.6-B once AppConfig carries this handle
    pub(crate) external_port: u16,
    #[allow(dead_code)] // consumed by P8.6-B once AppConfig carries this handle
    pub(crate) internal_port: u16,
    #[allow(dead_code)] // consumed by P8.6-B's Settings-reload path
    pub(crate) scopes: Arc<RwLock<ScopeSet>>,
}

/// Binds the external (agent-facing) loopback listener and picks an internal
/// port for the vendored Slint MCP server, **if and only if**
/// `automation.enabled` is set. Must be called before `logging::init()` —
/// see the module doc.
///
/// # Safety / ordering invariant
/// Setting `SLINT_MCP_PORT` uses `std::env::set_var`, which is `unsafe`
/// because it races with any other thread reading the environment. This
/// function is only ever called from `main`, before `logging::init()`
/// (which, in release builds, spawns a background log-appender thread) and
/// before anything else that could spawn a thread — the process is still
/// strictly single-threaded here, exactly the invariant
/// `render_backend::force_software_backend` documents and upholds for
/// `SLINT_BACKEND`. Do not call this after `logging::init()`.
pub(crate) fn prepare(repo: Option<&dyn ConnectionRepository>) -> Option<Prepared> {
    let repo = repo?;
    let automation = SettingsService::new(repo).load_automation().ok()?;
    if !automation.enabled {
        return None;
    }

    let external_listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            // No tracing subscriber yet (this runs before `logging::init()`)
            // -- stderr is the only option, matching main.rs's other
            // pre-logging fatal-adjacent messages.
            eprintln!("agent-mode: failed to bind the external loopback listener: {e}");
            return None;
        }
    };

    // Pick a free port for the internal vendored server by binding a
    // throwaway listener to port 0, reading the OS-assigned port, then
    // dropping it immediately so the Slint backend can bind it in turn.
    // This has an inherent (tiny, loopback-only, single-user-dev-machine)
    // TOCTOU window between the drop and the Slint backend's own bind --
    // accepted for v1, same trade-off every "hand a free port to a
    // subprocess/library I don't control the binding of" tool makes.
    let internal_port = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(probe) => match probe.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => {
                eprintln!("agent-mode: failed to read a free internal port: {e}");
                return None;
            }
        },
        Err(e) => {
            eprintln!("agent-mode: failed to allocate an internal port: {e}");
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

/// Starts the proxy's accept-loop thread. Safe to call any time after
/// `logging::init()`. Returns the handle described in the module doc.
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

    tracing::info!(
        external_port,
        internal_port,
        "agent-mode: scope-enforcement proxy listening (loopback only)"
    );

    let scopes_for_thread = Arc::clone(&scopes);
    std::thread::spawn(move || proxy::run(external_listener, internal_port, scopes_for_thread));

    AgentModeHandle {
        external_port,
        internal_port,
        scopes,
    }
}
