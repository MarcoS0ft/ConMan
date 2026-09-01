//! Structured logging installation.
//!
//! The composition root is the only place a `tracing` subscriber is installed;
//! every other crate only calls the `tracing::*` macros against whatever
//! subscriber (if any) is globally registered.
//!
//! - **Debug builds:** a daily-rotating file layer under
//!   `cm_platform::app_log_dir` (`<data>/conman/logs/conman.log.<date>`)
//!   PLUS a human-readable layer on stderr (the console stays attached in
//!   debug, see `main.rs`'s `windows_subsystem` cfg) — a debug repro must
//!   always leave something on disk, not just scroll past on the console.
//! - **Release builds:** the same file layer, alone. `windows_subsystem =
//! "windows"` detaches the console, so stderr is not observable there.
//!
//! Both layers share one `EnvFilter`, read from `CONMAN_LOG` (RUST_LOG-compatible
//! syntax, e.g. `CONMAN_LOG=debug` or `CONMAN_LOG=cm_session=trace,info`),
//! defaulting to `info` when unset or invalid.
//!
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Registry, fmt};

/// Env var overriding the log filter directive. RUST_LOG-compatible syntax.
const LOG_ENV_VAR: &str = "CONMAN_LOG";

/// Default filter when `CONMAN_LOG` is unset.
const DEFAULT_FILTER: &str = "info";

fn payload_safe(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.target() != "ironrdp_cliprdr" && !metadata.target().starts_with("ironrdp_cliprdr::")
}

fn build_filter() -> EnvFilter {
    EnvFilter::try_from_env(LOG_ENV_VAR).unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER))
}

/// Keeps the non-blocking file writer alive. Must be held for the lifetime of
/// `main` — dropping it early truncates in-flight log writes. The file layer
/// is installed in both debug and release builds now, so this guard is no
/// longer release-only.
#[must_use]
#[derive(Debug, Default)]
pub(crate) struct LoggingGuard {
    _appender_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Builds the always-on, daily-rolling file layer plus its keep-alive worker
/// guard. Generic over the subscriber it will be layered onto (rather than
/// hardcoding `Registry`) so the composition can also be exercised by a test
/// with a scoped (non-global) subscriber, instead of installing a real
/// process-wide one.
fn file_layer<S>(
    log_dir: impl AsRef<std::path::Path>,
) -> (
    impl tracing_subscriber::Layer<S> + Send + Sync + 'static,
    tracing_appender::non_blocking::WorkerGuard,
)
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let file_appender = tracing_appender::rolling::daily(log_dir, "conman.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    (
        fmt::layer()
            .with_ansi(false)
            .with_writer(non_blocking)
            .with_filter(tracing_subscriber::filter::filter_fn(payload_safe)),
        guard,
    )
}

/// Installs the global `tracing` subscriber. Call once, as early as possible
/// in `main` (before anything else that might log, e.g. the single-instance
/// guard) — never panics; a subscriber-install failure (only possible if
/// called twice) is swallowed since logging must never block startup.
pub(crate) fn init() -> LoggingGuard {
    let log_dir = cm_platform::app_log_dir().unwrap_or_else(|_| std::env::temp_dir());
    let (file_layer, guard) = file_layer(log_dir);

    // One shared filter feeds the whole registry, so `CONMAN_LOG` governs
    // every sink identically.
    let subscriber = Registry::default().with(build_filter()).with(file_layer);

    #[cfg(debug_assertions)]
    let subscriber = subscriber.with(
        fmt::layer()
            .with_ansi(cm_platform::stderr_supports_ansi())
            .with_writer(std::io::stderr)
            .with_filter(tracing_subscriber::filter::filter_fn(payload_safe)),
    );

    let _ = subscriber.try_init();

    LoggingGuard {
        _appender_guard: Some(guard),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file layer receives events unconditionally. Uses a scoped
    /// (`tracing::subscriber::with_default`) subscriber rather than calling
    /// `init` so it doesn't install a real process-wide subscriber that
    /// would leak into every other test in this binary.
    #[test]
    fn file_layer_receives_events_without_a_global_subscriber() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (layer, guard) = file_layer(dir.path());
        let subscriber = Registry::default().with(build_filter()).with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("logging smoke test line");
        });
        // WorkerGuard::drop blocks (briefly) until the background writer has
        // flushed everything sent before the shutdown signal.
        drop(guard);

        let found_line = std::fs::read_dir(dir.path())
            .expect("read temp log dir")
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                std::fs::read_to_string(entry.path())
                    .unwrap_or_default()
                    .contains("logging smoke test line")
            });
        assert!(
            found_line,
            "the file layer must receive events even without a debug-only cfg gate"
        );
    }

    #[test]
    fn ironrdp_cliprdr_payload_target_is_never_written() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (layer, guard) = file_layer(dir.path());
        let subscriber = Registry::default()
            .with(EnvFilter::new("trace"))
            .with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::event!(
                target: "ironrdp_cliprdr",
                tracing::Level::WARN,
                file_name = "CLIPBOARD_SENTINEL_SECRET.txt",
                "CLIPBOARD_SENTINEL_PAYLOAD"
            );
            tracing::info!(target: "conman::clipboard", "safe clipboard summary");
        });
        drop(guard);

        let output = std::fs::read_dir(dir.path())
            .expect("read temp log dir")
            .filter_map(Result::ok)
            .map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
            .collect::<String>();
        assert!(output.contains("safe clipboard summary"));
        assert!(!output.contains("CLIPBOARD_SENTINEL"));
    }
}
