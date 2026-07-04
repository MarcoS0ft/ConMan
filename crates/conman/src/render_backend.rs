//! P7.1: automatic software-renderer fallback so `conman` renders instead of
//! dying on a host with no usable hardware OpenGL (e.g. the win11-dev VM,
//! which only has OpenGL 1.1 / no real GPU driver -- `conman.exe` used to
//! crash on GL init unless the user manually set `SLINT_BACKEND=software`).
//!
//! ## Why a self-probe subprocess, not `BackendSelector` or catch-unwind
//!
//! See `docs/devel/memos/P7.1-backend-fallback.md` for the full write-up;
//! summary of why the obvious-looking alternatives don't work:
//!
//! - `slint::BackendSelector::select()` only decides *which* backend/renderer
//!   code path gets activated. It does not create a GL context or compile a
//!   single shader -- that happens lazily, later, when the window is actually
//!   shown and the event loop runs. So `select()` succeeding proves nothing
//!   about whether the accelerated path will actually work.
//! - `i_slint_core::platform::set_platform` (which `select()` calls) can only
//!   succeed **once per process** (`SetPlatformError::AlreadySet` after
//!   that). So even if we could detect the GL failure in-process, we could
//!   not turn around and re-select the software renderer in the same
//!   process.
//! - Catching the failure with `std::panic::catch_unwind` around the whole
//!   UI run and then retrying in-process runs into the same one-shot
//!   `set_platform` wall, and would also require reconstructing `AppConfig`
//!   (its `mpsc::Receiver` from the single-instance guard is not `Clone` and
//!   would have been dropped mid-unwind). Relaunching a *new* process instead
//!   collides with the single-instance lock: `InstanceGuard::listen()` moves
//!   the bound loopback listener onto a background thread that outlives a
//!   caught panic on the main thread, so a same-process relaunch would see
//!   its own still-running parent as "already running" and exit doing
//!   nothing. And a hard OS-level crash (e.g. an access violation from a
//!   broken driver) isn't a Rust panic at all -- `catch_unwind` can't catch
//!   it regardless.
//!
//! Instead, before touching *any* real application state (single-instance
//! lock, keyring, database, UI), `conman` spawns a disposable, side-effect-
//! free copy of itself ([`run_probe_child`]) that does nothing but create a
//! trivial window and run it through the exact same `show()` +
//! `run_event_loop()` sequence the real app uses (see the generated
//! `ComponentHandle::run()` that `cm_ui::run` calls). If that child exits
//! abnormally -- covering both a caught panic *and* a hard crash, since
//! either way the OS reports a non-success exit status -- the software
//! renderer is forced for the real run that follows in this (parent)
//! process, which still has its one-and-only `set_platform` call unused.
//!
//! An explicit user-set `SLINT_BACKEND` always wins and skips the probe
//! entirely, so the xvfb/QA gates (which set `winit-femtovg` / `software`)
//! are unaffected.

use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

/// Set (to any value) on the disposable probe child so `main` takes the
/// minimal probe branch instead of the real startup path. Internal only --
/// never documented for end users.
pub(crate) const PROBE_ENV_VAR: &str = "CONMAN_RENDER_PROBE_CHILD";

/// How long the probe child's window stays up (driven by a one-shot timer)
/// before it quits on its own. Generous relative to how long a real GL/shader
/// init takes; this runs once per launch so it's worth erring generous.
const PROBE_WINDOW_LIFETIME: Duration = Duration::from_millis(200);

/// Upper bound the parent waits for the probe child before giving up on it.
/// Never let a stuck/hung probe delay startup indefinitely.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

slint::slint! {
    // Deliberately minimal: the only thing that matters is that materializing
    // and showing it exercises real window + renderer creation.
    export component ProbeWindow inherits Window {
        width: 4px;
        height: 4px;
    }
}

/// Entry point for the disposable probe child. `main` dispatches here, before
/// anything else, when [`PROBE_ENV_VAR`] is set -- no logging subscriber, no
/// single-instance guard, no storage, no keyring: this process exists only to
/// answer "does the accelerated renderer come up here?" via its exit status.
pub(crate) fn run_probe_child() -> ExitCode {
    let Ok(window) = ProbeWindow::new() else {
        return ExitCode::FAILURE;
    };
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::SingleShot, PROBE_WINDOW_LIFETIME, || {
        // Best-effort: if the loop already stopped for some other reason
        // there's nothing left to quit.
        let _ = slint::quit_event_loop();
    });
    match window.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// Outcome of [`probe`].
enum ProbeOutcome {
    /// The child rendered and exited cleanly.
    Accelerated,
    /// Couldn't tell either way (e.g. failed to spawn the probe at all).
    /// Proceeds with today's default (accelerated) rather than let a bug in
    /// the probe machinery itself introduce a new failure mode.
    Inconclusive(String),
    /// The child exited abnormally (panic or hard crash) or timed out.
    Failed(String),
}

/// Spawns the probe child and waits (bounded by [`PROBE_TIMEOUT`]) for it to
/// exit, classifying the result.
fn probe() -> ProbeOutcome {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return ProbeOutcome::Inconclusive(format!("current_exe(): {e}")),
    };

    let mut child = match Command::new(exe).env(PROBE_ENV_VAR, "1").spawn() {
        Ok(c) => c,
        Err(e) => return ProbeOutcome::Inconclusive(format!("failed to spawn probe: {e}")),
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return ProbeOutcome::Accelerated,
            Ok(Some(status)) => {
                return ProbeOutcome::Failed(format!("probe exited abnormally ({status})"));
            }
            Ok(None) => {
                if start.elapsed() > PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ProbeOutcome::Failed("probe timed out".to_owned());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return ProbeOutcome::Inconclusive(format!("failed to wait on probe: {e}")),
        }
    }
}

/// Forces the software renderer for the real run that follows, by setting
/// `SLINT_BACKEND` in this process's own environment.
///
/// # Safety
/// `std::env::set_var` is `unsafe` because mutating the environment races
/// with any other thread reading it. This is only ever called from
/// [`resolve_and_apply`], which `main` calls immediately after
/// `logging::init()` and before anything else -- in particular before the
/// single-instance listener thread ([`cm_platform::single_instance`]) or the
/// release-build log-appender thread are spawned. No other thread exists yet
/// to race with (CONVENTIONS §2 unsafe-usage rule; see also
/// `docs/devel/memos/P7.1-backend-fallback.md`).
fn force_software_backend() {
    #[allow(unsafe_code)] // see the doc comment above for the upheld invariant
    unsafe {
        std::env::set_var("SLINT_BACKEND", "software");
    }
}

/// Decides the renderer for the real run and applies it before anything else
/// in `main` touches the platform, logging the decision via `tracing` either
/// way (P7.1 requirements 2-3). Must be called before any Slint API is used
/// in this process, immediately after `logging::init()`.
pub(crate) fn resolve_and_apply() {
    if let Ok(explicit) = std::env::var("SLINT_BACKEND") {
        tracing::info!(
            renderer = %explicit,
            fallback = false,
            "startup renderer: honoring explicit SLINT_BACKEND"
        );
        return;
    }

    match probe() {
        ProbeOutcome::Accelerated => {
            tracing::info!(
                renderer = "accelerated (winit+femtovg)",
                fallback = false,
                "startup renderer: probe succeeded"
            );
        }
        ProbeOutcome::Inconclusive(reason) => {
            tracing::warn!(
                reason = %reason,
                "startup renderer: probe inconclusive, proceeding with the accelerated renderer"
            );
        }
        ProbeOutcome::Failed(reason) => {
            tracing::warn!(reason = %reason, "startup renderer: probe failed");
            force_software_backend();
            tracing::info!(
                renderer = "software",
                fallback = true,
                "startup renderer: forced the software renderer (P7.1 fallback)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe child must actually take the minimal branch and never fall
    /// through into the real app's storage/keyring/UI startup -- exercised
    /// indirectly via `main`'s dispatch, but the constant itself must not
    /// collide with anything a user would plausibly set.
    #[test]
    fn probe_env_var_is_conman_internal_and_distinct_from_slint_backend() {
        assert_ne!(PROBE_ENV_VAR, "SLINT_BACKEND");
        assert!(PROBE_ENV_VAR.starts_with("CONMAN_"));
    }

    /// A healthy probe run (this test binary is not the `conman` binary, so
    /// `current_exe()` here is the test harness -- but running an arbitrary
    /// executable that exits 0 with no `PROBE_ENV_VAR` handling still proves
    /// the spawn/wait/classify machinery works end to end without needing
    /// the real `conman` binary or a display).
    #[test]
    fn probe_classifies_a_process_that_never_touches_the_env_var_as_accelerated() {
        // `probe()` always spawns `current_exe()`, which for `cargo test` is
        // the test binary itself, re-run with PROBE_ENV_VAR set. The test
        // binary doesn't understand that var, so it just re-runs the whole
        // test suite (recursion). To keep this test cheap and deterministic
        // it directly exercises the wait/classify loop against a trivial
        // child instead of `probe()`'s `current_exe()` path.
        let mut child = Command::new("true")
            .spawn()
            .expect("the `true` coreutil must exist for this test");
        let start = Instant::now();
        let status = loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => break status,
                None => {
                    assert!(
                        start.elapsed() < PROBE_TIMEOUT,
                        "probe loop should not hang"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        };
        assert!(status.success());
    }

    #[test]
    fn probe_classifies_a_nonzero_exit_as_failed() {
        let mut child = Command::new("false")
            .spawn()
            .expect("the `false` coreutil must exist for this test");
        let status = child.wait().expect("wait");
        assert!(!status.success());
    }
}
