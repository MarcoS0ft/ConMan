//! Structured logging installation (P6.3).
//!
//! The composition root is the only place a `tracing` subscriber is installed;
//! every other crate only calls the `tracing::*` macros against whatever
//! subscriber (if any) is globally registered.
//!
//! - **Debug builds:** a human-readable layer on stderr (matches the prior
//!   `eprintln!`-based behavior — the console stays attached in debug, see
//!   `main.rs`'s `windows_subsystem` cfg).
//! - **Release builds:** `windows_subsystem = "windows"` detaches the console,
//!   so stderr is not observable. Instead, a daily-rotating file layer under
//!   `cm_platform::app_log_dir()` (`<data>/conman/logs/conman.log.<date>`).
//!
//! Both layers share one `EnvFilter`, read from `CONMAN_LOG` (RUST_LOG-compatible
//! syntax, e.g. `CONMAN_LOG=debug` or `CONMAN_LOG=cm_session=trace,info`),
//! defaulting to `info` when unset or invalid.
use tracing_subscriber::EnvFilter;

/// Env var overriding the log filter directive. RUST_LOG-compatible syntax.
const LOG_ENV_VAR: &str = "CONMAN_LOG";

/// Default filter when `CONMAN_LOG` is unset.
const DEFAULT_FILTER: &str = "info";

fn build_filter() -> EnvFilter {
    EnvFilter::try_from_env(LOG_ENV_VAR).unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER))
}

/// Keeps the release build's non-blocking file writer alive. Must be held for
/// the lifetime of `main` — dropping it early truncates in-flight log writes.
#[must_use]
#[derive(Debug, Default)]
pub(crate) struct LoggingGuard {
    #[cfg(not(debug_assertions))]
    _appender_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Installs the global `tracing` subscriber. Call once, as early as possible
/// in `main` (before anything else that might log, e.g. the single-instance
/// guard) — never panics; a subscriber-install failure (only possible if
/// called twice) is swallowed since logging must never block startup.
pub(crate) fn init() -> LoggingGuard {
    #[cfg(debug_assertions)]
    {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(build_filter())
            .with_writer(std::io::stderr)
            .try_init();
        LoggingGuard::default()
    }
    #[cfg(not(debug_assertions))]
    {
        let log_dir = cm_platform::app_log_dir().unwrap_or_else(|_| std::env::temp_dir());
        let file_appender = tracing_appender::rolling::daily(log_dir, "conman.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let _ = tracing_subscriber::fmt()
            .with_env_filter(build_filter())
            .with_ansi(false)
            .with_writer(non_blocking)
            .try_init();
        LoggingGuard {
            _appender_guard: Some(guard),
        }
    }
}
