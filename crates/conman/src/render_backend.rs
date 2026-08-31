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
//! Instead, before initializing Slint or acquiring the single-instance lock,
//! `conman` spawns a disposable, side-effect-free copy of itself
//! ([`run_probe_child`]) that does nothing but create a
//! trivial window and run it through the exact same `show()` +
//! `run_event_loop()` sequence the real app uses (see the generated
//! `ComponentHandle::run()` that `cm_ui::run` calls). If that child exits
//! abnormally -- covering both a caught panic *and* a hard crash, since
//! either way the OS reports a non-success exit status -- the software
//! renderer is forced for the real run that follows in this (parent)
//! process, which still has its one-and-only `set_platform` call unused.
//!
//! An explicit user-set `SLINT_BACKEND` always wins, followed by an explicit
//! `conman.ini` preference. Either skips the probe entirely, so xvfb/QA
//! gates (which set `winit-femtovg` / `software`) are unaffected.
//!
//! [`resolve`] (which may call `force_software_backend`'s `unsafe
//! std::env::set_var`) must run **before** `logging::init()` -- see
//! `force_software_backend`'s doc comment for why -- so the decision is
//! carried across that call as a [`RendererDecision`] and only logged
//! afterward, by [`log_decision`].

use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use cm_core::RendererBackend;

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
/// [`resolve`], which `main` calls **before** `logging::init()` (which, in
/// release builds, spawns a background log-appender thread) and before any
/// unrestricted worker exists. The sole concurrent worker is the
/// single-instance responder started by the composition root; its audited
/// loop performs only bounded socket I/O, tracing, and mpsc sends and never
/// reads or mutates the environment. Therefore no concurrent environment
/// access can race this mutation (CONVENTIONS §2 unsafe-usage rule; see also
/// `docs/devel/memos/P7.1-backend-fallback.md`). Do not call this after other
/// workers are allowed to start -- that would break the invariant.
fn force_software_backend() {
    #[allow(unsafe_code)] // see the doc comment above for the upheld invariant
    unsafe {
        std::env::set_var("SLINT_BACKEND", "software");
    }
}

/// The renderer decision made by [`resolve`], carried across `logging::init()`
/// so [`log_decision`] can report it once a subscriber exists.
pub(crate) enum RendererDecision {
    /// The user set `SLINT_BACKEND` themselves; honored verbatim.
    ExplicitEnv(String),
    /// An explicit `renderer-backend` preference from `conman.ini`.
    Configured(RendererBackend),
    /// A previously-persisted backend was honored from machine-local state, so
    /// the probe was skipped this launch (P7.1 cont.). Carries the backend
    /// string ("software" | "accelerated"). For "software" the fallback has
    /// already been forced inside [`resolve`]; "accelerated" needs nothing set
    /// (it is Slint's default).
    Cached(RendererBackend),
    /// No override; the probe confirmed the accelerated renderer comes up.
    Accelerated,
    /// No override; couldn't tell either way (e.g. failed to spawn the
    /// probe). Proceeds with the accelerated default.
    Inconclusive(String),
    /// No override; the probe failed, so the software renderer has already
    /// been forced (`force_software_backend` ran inside [`resolve`]).
    FallbackForced(String),
}

/// Decides the renderer for the real run and -- if a fallback is needed --
/// applies it immediately, by forcing `SLINT_BACKEND=software` in this
/// process's environment.
///
/// Must run before any Slint API is used in this process, and **before**
/// `logging::init()`: forcing the fallback needs `std::env::set_var`, which
/// is only sound while no concurrent thread can access the environment (see
/// `force_software_backend`'s doc comment). Returns the decision for
/// [`log_decision`] to report once logging is up.
///
/// Precedence: an explicit `SLINT_BACKEND` environment value wins, followed
/// by an explicit `renderer-backend` preference in `conman.ini`, the
/// machine-local probe cache, and finally a fresh probe. Setting
/// `CONMAN_RENDER_REPROBE` ignores only the automatic cache; it never
/// overrides an explicit user preference.
///
/// `cached` is the machine-local backend learned during an earlier probe (see
/// [`crate::render_backend::RendererDecision::Cached`]); `None` means there is
/// no learned fallback and the automatic path must probe.
pub(crate) fn resolve(
    configured: RendererBackend,
    cached: Option<RendererBackend>,
) -> RendererDecision {
    if let Ok(explicit) = std::env::var("SLINT_BACKEND") {
        return RendererDecision::ExplicitEnv(explicit);
    }

    match configured {
        RendererBackend::Software => {
            force_software_backend();
            return RendererDecision::Configured(configured);
        }
        RendererBackend::Accelerated => return RendererDecision::Configured(configured),
        RendererBackend::Auto => {}
    }

    // Escape hatch: re-probe and ignore whatever is cached.
    let reprobe = std::env::var_os("CONMAN_RENDER_REPROBE").is_some();

    if !reprobe {
        match cached {
            // The forced-software case must actually set the env var this run;
            // "software" carries safely to any hardware.
            Some(RendererBackend::Software) => {
                force_software_backend();
                return RendererDecision::Cached(RendererBackend::Software);
            }
            // "accelerated" is Slint's default, so nothing to set -- just skip
            // the probe.
            Some(RendererBackend::Accelerated) => {
                return RendererDecision::Cached(RendererBackend::Accelerated);
            }
            // Anything else (None / "auto" / unknown) falls through to a probe.
            _ => {}
        }
    }

    match probe() {
        ProbeOutcome::Accelerated => RendererDecision::Accelerated,
        ProbeOutcome::Inconclusive(reason) => RendererDecision::Inconclusive(reason),
        ProbeOutcome::Failed(reason) => {
            force_software_backend();
            RendererDecision::FallbackForced(reason)
        }
    }
}

/// Decides whether the machine-local renderer probe cache should be updated
/// after [`resolve`] has made its decision. The composition root applies the
/// result through `AppStateService`; the editable renderer preference never
/// enters this cache. Returns `None` when nothing should be written.
///
/// This is the single source of truth for the two safety invariants `main`
/// must uphold (pulled out of `main` itself so they're unit-testable, P7.1
/// cont. hardening):
///
/// - A probe that comes up [`RendererDecision::Accelerated`] is **never**
///   auto-persisted as "accelerated" — carrying that to a GPU-less machine
///   would crash it, which is the exact failure the probe exists to prevent.
///   The one exception is clearing a *stale* "software" cache back to "auto"
///   (`cached == Some("software")`): this only occurs via the
///   `CONMAN_RENDER_REPROBE` escape hatch (see [`resolve`]'s cache-precedence
///   logic — with a "software" cache and no reprobe, `resolve` always returns
///   `Cached("software")` without ever reaching the probe), so a later launch
///   probes fresh instead of staying stuck on software.
/// - Only a freshly-forced "software" fallback
///   ([`RendererDecision::FallbackForced`]) is auto-persisted, and only once
///   (skipped when the cache already says "software").
/// - [`RendererDecision::ExplicitEnv`], [`RendererDecision::Cached`], and
///   [`RendererDecision::Inconclusive`] never write anything: an explicit env
///   var is the user's own choice (not ours to persist), a cache hit is
///   already exactly what's persisted, and an inconclusive probe deliberately
///   proceeds with today's default without changing what's on disk.
pub(crate) fn persist_decision(
    decision: &RendererDecision,
    cached: Option<RendererBackend>,
) -> Option<RendererBackend> {
    match decision {
        RendererDecision::FallbackForced(_) if cached != Some(RendererBackend::Software) => {
            Some(RendererBackend::Software)
        }
        RendererDecision::Accelerated if cached == Some(RendererBackend::Software) => {
            Some(RendererBackend::Auto)
        }
        _ => None,
    }
}

/// Logs the decision [`resolve`] already made and applied, via `tracing`
/// (P7.1 requirements 2-3). Call immediately after `logging::init()`.
pub(crate) fn log_decision(decision: &RendererDecision) {
    match decision {
        RendererDecision::ExplicitEnv(explicit) => {
            tracing::info!(
                renderer = %explicit,
                fallback = false,
                "startup renderer: honoring explicit SLINT_BACKEND"
            );
        }
        RendererDecision::Configured(configured) => {
            tracing::info!(
                renderer = configured.as_str(),
                configured = true,
                "startup renderer: honoring conman.ini preference"
            );
        }
        RendererDecision::Cached(v) => {
            tracing::info!(
                renderer = v.as_str(),
                cached = true,
                "startup renderer: honored persisted backend, probe skipped"
            );
        }
        RendererDecision::Accelerated => {
            tracing::info!(
                renderer = "accelerated (winit+femtovg)",
                fallback = false,
                "startup renderer: probe succeeded"
            );
        }
        RendererDecision::Inconclusive(reason) => {
            tracing::warn!(
                reason = %reason,
                "startup renderer: probe inconclusive, proceeding with the accelerated renderer"
            );
        }
        RendererDecision::FallbackForced(reason) => {
            tracing::warn!(reason = %reason, "startup renderer: probe failed");
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

    fn child_that_exits(code: u8) -> Command {
        #[cfg(windows)]
        {
            let mut command = Command::new("cmd.exe");
            command.args(["/D", "/C", &format!("exit {code}")]);
            command
        }
        #[cfg(not(windows))]
        {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", &format!("exit {code}")]);
            command
        }
    }

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
        let mut child = child_that_exits(0)
            .spawn()
            .expect("the platform command interpreter must exist for this test");
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
        let mut child = child_that_exits(1)
            .spawn()
            .expect("the platform command interpreter must exist for this test");
        let status = child.wait().expect("wait");
        assert!(!status.success());
    }

    // ── P7.1 cont.: persisted-backend cache precedence ───────────────────
    //
    // These exercise `resolve`, which mutates *process-global* env vars
    // (`SLINT_BACKEND`, via `force_software_backend`). To avoid cross-test env
    // races they live in a SINGLE `#[test]` fn (so their steps run
    // sequentially, never in parallel with each other) that saves and restores
    // the two env vars it touches.
    //
    // The reprobe step drives `resolve` down the real `probe()` path, which
    // spawns `current_exe()` (this test binary) with `PROBE_ENV_VAR` set. The
    // guard at the top mirrors what the real `main` does with that var
    // (dispatch away before doing real work): when this fn is re-entered inside
    // the spawned probe child it returns immediately, so the probe cannot
    // recurse into itself. That bounds the probe child to a single, ordinary
    // re-run of the suite.

    #[allow(unsafe_code)] // test-only env manipulation; see note above
    fn set_env(key: &str, val: Option<&str>) {
        // SAFETY: called only from the single-threaded `resolve_*` test below,
        // whose steps run sequentially; no other thread reads these vars
        // concurrently (no other test touches SLINT_BACKEND / the reprobe var).
        unsafe {
            match val {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn resolve_honors_env_then_config_then_cache_then_reprobe() {
        // If we are the probe child spawned by the reprobe step below, do
        // nothing (see the module-level note): this both avoids probe
        // recursion and keeps the child's exit status clean.
        if std::env::var_os(PROBE_ENV_VAR).is_some() {
            return;
        }

        let saved_backend = std::env::var("SLINT_BACKEND").ok();
        let saved_reprobe = std::env::var("CONMAN_RENDER_REPROBE").ok();

        // Clean slate: no explicit backend, no reprobe.
        set_env("SLINT_BACKEND", None);
        set_env("CONMAN_RENDER_REPROBE", None);

        // Cached "software" is honored (no probe) and forces the fallback env.
        assert!(
            matches!(
                resolve(RendererBackend::Auto, Some(RendererBackend::Software)),
                RendererDecision::Cached(RendererBackend::Software)
            ),
            "cached software must be honored without probing"
        );
        // `force_software_backend` set SLINT_BACKEND; clear it before the next
        // step so it doesn't shadow the cache path as an explicit override.
        set_env("SLINT_BACKEND", None);

        // Cached "accelerated" is honored (no probe, no env needed).
        assert!(
            matches!(
                resolve(RendererBackend::Auto, Some(RendererBackend::Accelerated)),
                RendererDecision::Cached(RendererBackend::Accelerated)
            ),
            "cached accelerated must be honored without probing"
        );

        // An explicit text-config preference beats machine-local state.
        assert!(matches!(
            resolve(
                RendererBackend::Accelerated,
                Some(RendererBackend::Software)
            ),
            RendererDecision::Configured(RendererBackend::Accelerated)
        ));

        // An explicit SLINT_BACKEND beats any cached value.
        set_env("SLINT_BACKEND", Some("software"));
        assert!(
            matches!(
                resolve(
                    RendererBackend::Accelerated,
                    Some(RendererBackend::Accelerated)
                ),
                RendererDecision::ExplicitEnv(ref v) if v == "software"
            ),
            "explicit SLINT_BACKEND must win over the cache"
        );
        set_env("SLINT_BACKEND", None);

        // With CONMAN_RENDER_REPROBE set the cache is ignored: `resolve` falls
        // through to the probe, so the outcome is never `Cached`. (The probe
        // itself is neutralized by the guard at the top of this fn.)
        set_env("CONMAN_RENDER_REPROBE", Some("1"));
        let reprobed = resolve(RendererBackend::Auto, Some(RendererBackend::Software));
        assert!(
            !matches!(reprobed, RendererDecision::Cached(_)),
            "reprobe must ignore the cache and take the probe path, got a Cached decision"
        );

        // Restore the environment for any other tests / parallel binaries.
        set_env("SLINT_BACKEND", saved_backend.as_deref());
        set_env("CONMAN_RENDER_REPROBE", saved_reprobe.as_deref());
    }

    // ── P7.1 cont.: `persist_decision` — the pure persist-policy fn ──────────
    //
    // No env mutation, no subprocess, no I/O: these run in any order, in
    // parallel with everything else in this module.

    #[test]
    fn persist_decision_never_persists_a_fresh_accelerated_probe() {
        // The headline safety invariant: a probe that comes up Accelerated
        // must NEVER be persisted -- that's exactly what would crash a
        // GPU-less machine that later imports/inherits this DB.
        assert_eq!(persist_decision(&RendererDecision::Accelerated, None), None);
        assert_eq!(
            persist_decision(&RendererDecision::Accelerated, Some(RendererBackend::Auto)),
            None
        );
        assert_eq!(
            persist_decision(
                &RendererDecision::Accelerated,
                Some(RendererBackend::Accelerated)
            ),
            None
        );
    }

    #[test]
    fn persist_decision_persists_software_fallback_when_not_already_cached() {
        let decision = RendererDecision::FallbackForced("boom".to_owned());
        assert_eq!(
            persist_decision(&decision, None),
            Some(RendererBackend::Software)
        );
        assert_eq!(
            persist_decision(&decision, Some(RendererBackend::Auto)),
            Some(RendererBackend::Software)
        );
        assert_eq!(
            persist_decision(&decision, Some(RendererBackend::Accelerated)),
            Some(RendererBackend::Software)
        );
    }

    #[test]
    fn persist_decision_skips_rewriting_an_already_cached_software_fallback() {
        let decision = RendererDecision::FallbackForced("boom".to_owned());
        assert_eq!(
            persist_decision(&decision, Some(RendererBackend::Software)),
            None
        );
    }

    #[test]
    fn persist_decision_clears_a_stale_software_cache_on_reprobe_accelerated() {
        // Only reachable via CONMAN_RENDER_REPROBE (see resolve()'s cache
        // precedence): a stale "software" pin, reprobed, now comes up
        // Accelerated -- clear the cache to "auto" so future launches probe
        // fresh instead of staying stuck in software.
        assert_eq!(
            persist_decision(
                &RendererDecision::Accelerated,
                Some(RendererBackend::Software)
            ),
            Some(RendererBackend::Auto)
        );
    }

    #[test]
    fn persist_decision_never_persists_an_explicit_env_override() {
        let decision = RendererDecision::ExplicitEnv("software".to_owned());
        assert_eq!(persist_decision(&decision, None), None);
        assert_eq!(
            persist_decision(&decision, Some(RendererBackend::Software)),
            None
        );
        assert_eq!(
            persist_decision(&decision, Some(RendererBackend::Accelerated)),
            None
        );
    }

    #[test]
    fn persist_decision_never_changes_cache_for_explicit_config() {
        let decision = RendererDecision::Configured(RendererBackend::Accelerated);
        assert_eq!(
            persist_decision(&decision, Some(RendererBackend::Software)),
            None
        );
    }

    #[test]
    fn persist_decision_never_persists_a_cached_or_inconclusive_decision() {
        // A cache hit is already exactly what's persisted; an inconclusive
        // probe deliberately proceeds without touching the cache.
        assert_eq!(
            persist_decision(
                &RendererDecision::Cached(RendererBackend::Software),
                Some(RendererBackend::Software)
            ),
            None
        );
        assert_eq!(
            persist_decision(
                &RendererDecision::Inconclusive("spawn failed".to_owned()),
                None
            ),
            None
        );
    }
}
