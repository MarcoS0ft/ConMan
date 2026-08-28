//! Console/terminal capability detection.
//!
//! Includes [`stderr_supports_ansi`], used by `conman`'s debug
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

/// Write one line to the process's standard output.
///
/// A release Windows GUI-subsystem executable starts without a console even
/// when invoked from a shell. Before writing, this makes a best-effort attach
/// to the parent's existing console. It never allocates a new console, so a
/// normal Explorer/double-click launch cannot flash a console window. Pipes
/// and redirected handles continue to work through Rust's standard stream.
pub fn write_stdout_line(text: &str) -> std::io::Result<()> {
    attach_parent_console_if_available();
    write_line(std::io::stdout().lock(), text)
}

/// Write one line to the process's standard error.
///
/// Uses the same parent-console behavior as [`write_stdout_line`].
pub fn write_stderr_line(text: &str) -> std::io::Result<()> {
    attach_parent_console_if_available();
    write_line(std::io::stderr().lock(), text)
}

fn write_line(mut writer: impl std::io::Write, text: &str) -> std::io::Result<()> {
    writer.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        writer.write_all(b"\n")?;
    }
    writer.flush()
}

#[cfg(not(windows))]
fn attach_parent_console_if_available() {}

/// Attach only to a console already owned by the parent process.
///
/// Failure is deliberately ignored: the process may already have a console,
/// may have inherited redirected pipe handles, or may have been launched by a
/// GUI parent with no console. In all three cases the subsequent ordinary
/// standard-stream write is the correct best effort.
#[cfg(windows)]
#[allow(unsafe_code)] // AttachConsole has no safe std/windows-rs wrapper; invariant documented below.
fn attach_parent_console_if_available() {
    use windows::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};

    // SAFETY: `AttachConsole` takes only the documented sentinel process id,
    // retains no pointers, and mutates process-global console association.
    // This is called at executable startup before any worker threads exist.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

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

    #[test]
    fn line_writer_adds_exactly_one_trailing_newline() {
        let mut output = Vec::new();
        write_line(&mut output, "hello").unwrap();
        write_line(&mut output, "world\n").unwrap();
        assert_eq!(output, b"hello\nworld\n");
    }
}
