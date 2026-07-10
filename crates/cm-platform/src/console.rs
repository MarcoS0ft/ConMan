//! Console/terminal capability detection.
//!
//! Just one query today: [`stderr_supports_ansi`], used by `conman`'s debug
//! logging setup (`crates/conman/src/logging.rs`) to decide whether the
//! stderr `tracing_subscriber` layer should emit ANSI color codes. Without
//! this check, a legacy Windows console (e.g. Server 2022's default conhost,
//! which does not enable VT processing by default) prints raw escape-code
//! literals instead of color — `tracing_subscriber`'s `fmt::layer()` defaults
//! to ANSI **on** with no terminal detection of its own.
//!
//! - **Redirected stderr (file/pipe)**: always `false` — there's no terminal
//!   to paint, and raw escapes in a log file are worse than plain text.
//! - **Windows**: attempts to enable `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on
//!   the stderr console handle; `true` only if that succeeds (or was already
//!   on).
//! - **Everything else**: `true` whenever stderr is a terminal — modern
//!   Unix terminals are assumed to support ANSI (matches
//!   `tracing_subscriber`'s own prior default behavior there).

/// True if this process's stderr is a terminal that supports ANSI/VT escapes.
///
/// On Windows, enables VT processing on the stderr console as a side effect
/// when possible, so the tracing console layer can emit color instead of raw
/// escape literals on a legacy conhost. Returns `false` when stderr is
/// redirected (file/pipe) or the console can't do VT.
#[must_use]
pub fn stderr_supports_ansi() -> bool {
    use std::io::IsTerminal;
    if !std::io::stderr().is_terminal() {
        return false;
    }
    #[cfg(windows)]
    {
        enable_vt_stderr()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Enables `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on the stderr console handle.
///
/// **Compile- and runtime-UNVERIFIED in this task**: this agent's environment
/// has only the `x86_64-unknown-linux-gnu` Rust target installed, so this
/// `cfg`-gated function is never parsed by `cargo build`/`cargo check` here,
/// and there is no Windows host to run it on. Written carefully against the
/// vendored `windows` 0.62 crate source (`Win32::System::Console`'s generated
/// bindings for `GetStdHandle`/`GetConsoleMode`/`SetConsoleMode`) — a Windows
/// build/run is required to confirm it actually compiles and behaves as
/// documented.
#[cfg(windows)]
fn enable_vt_stderr() -> bool {
    use windows::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle,
        STD_ERROR_HANDLE, SetConsoleMode,
    };
    // SAFETY: `GetStdHandle`/`GetConsoleMode`/`SetConsoleMode` are simple
    // Win32 calls taking a process-standard handle and stack-local
    // in/out-params that outlive this synchronous sequence -- no aliasing,
    // no retained pointers.
    unsafe {
        let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) else {
            return false;
        };
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode).is_err() {
            return false;
        }
        if mode.contains(ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
            return true; // Already enabled.
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_supports_ansi_never_panics() {
        // Smoke test: whatever the host environment (redirected to a file
        // under `cargo test`, a real terminal, headless CI, etc.), this must
        // return a bool, never panic. The actual value is runtime-dependent
        // (test harnesses typically redirect stderr, so `false` is the
        // expected/common result here) -- not asserted either way.
        let _ = stderr_supports_ansi();
    }
}
