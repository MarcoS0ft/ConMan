#![forbid(unsafe_code)]

mod gui;

#[cfg(feature = "headless")]
mod app;
#[cfg(feature = "headless")]
mod cli;
#[cfg(feature = "headless")]
mod error;
#[cfg(feature = "headless")]
mod render;
#[cfg(feature = "headless")]
mod types;

#[cfg(feature = "headless")]
pub use app::{DiagnosticSink, PasswordInput, StdinPasswordInput, dispatch};
#[cfg(feature = "headless")]
pub use cli::CliParser;
#[cfg(feature = "headless")]
pub use error::CliError;
pub use gui::{
    GuiArgumentError, GuiInvocation, GuiParseOutcome, gui_help, neutralize_terminal_text,
    parse_gui_args,
};
#[cfg(feature = "headless")]
pub use render::{RenderedOutput, render};
#[cfg(feature = "headless")]
pub use types::{Execution, Invocation, OutputFormat};

/// Parse, dispatch, and render one ambient process invocation.
///
/// This is the sole production assembly point used by the tiny `conmanctl`
/// binary. Successful data is written only to stdout and diagnostics only to
/// stderr.
#[must_use]
#[cfg(feature = "headless")]
pub fn run_process() -> i32 {
    run_process_with_os(std::env::args_os().skip(1))
}

#[must_use]
#[cfg(feature = "headless")]
fn run_process_with_os<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let args = match args
        .into_iter()
        .map(Into::into)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(_) => {
            eprintln!(
                "error: command-line arguments are not valid Unicode; use Unicode file paths"
            );
            return 2;
        }
    };
    run_process_with(args)
}

#[must_use]
#[cfg(feature = "headless")]
fn run_process_with(args: Vec<String>) -> i32 {
    let parser = CliParser::new();
    let invocation = match parser.parse_rich(args) {
        Ok(Some(invocation)) => invocation,
        Ok(None) => return 0,
        Err(error) => return error.exit_code(),
    };
    let format = invocation.global.format;
    let mut password_input = StdinPasswordInput;
    let mut diagnostic_sink = |diagnostic: &types::Diagnostic| {
        use std::io::Write as _;
        let rendered = render::render_diagnostic(diagnostic);
        let mut stderr = std::io::stderr().lock();
        stderr
            .write_all(rendered.as_bytes())
            .and_then(|()| stderr.flush())
            .map_err(|error| CliError::Output(error.to_string()))
    };
    match dispatch(invocation, &mut password_input, &mut diagnostic_sink)
        .and_then(|execution| render(execution, format))
    {
        Ok(output) => {
            use std::io::Write as _;
            if !output.stdout.is_empty()
                && std::io::stdout()
                    .write_all(output.stdout.as_bytes())
                    .is_err()
            {
                return 74;
            }
            if !output.stderr.is_empty()
                && std::io::stderr()
                    .write_all(output.stderr.as_bytes())
                    .is_err()
            {
                return 74;
            }
            0
        }
        Err(error) => {
            eprintln!("error: {}", render::render_error(&error));
            error.exit_code()
        }
    }
}
