//! Effect-free argument parsing for the graphical `conman` executable.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

/// Startup path overrides accepted by the GUI executable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuiInvocation {
    pub config_path: Option<PathBuf>,
    pub database_path: Option<PathBuf>,
}

/// A successfully parsed GUI command line.
///
/// Help and version are returned as owned text because a release Windows GUI
/// binary has no console. The composition root decides whether to show the
/// text in a native dialog, log it, or write it to an attached console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuiParseOutcome {
    Run(GuiInvocation),
    Help(String),
    Version(String),
}

/// Invalid GUI command line. Parsing performs no presentation effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiArgumentError {
    message: String,
}

impl GuiArgumentError {
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        2
    }

    /// A presentation-ready diagnostic with usage, safe for a native dialog.
    #[must_use]
    pub fn render(&self) -> String {
        format!("error: {}\n\n{}", self.message, gui_help())
    }
}

impl fmt::Display for GuiArgumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for GuiArgumentError {}

/// Parse only the startup arguments supported by the graphical executable.
///
/// The iterator excludes the executable name, matching
/// `std::env::args_os.skip(1)`. Paths remain [`OsString`]s until converted
/// to [`PathBuf`], so non-Unicode platform paths are preserved. Unknown
/// options, positional arguments, duplicate overrides, and combinations of
/// help/version with other arguments are rejected.
pub fn parse_gui_args<I, S>(args: I) -> Result<GuiParseOutcome, GuiArgumentError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args = args.into_iter().map(Into::into).peekable();
    let mut invocation = GuiInvocation::default();
    let mut display = None;

    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--config") => {
                reject_display_combination(display.as_ref())?;
                if invocation.config_path.is_some() {
                    return Err(error("--config may be specified only once"));
                }
                invocation.config_path = Some(read_path(&mut args, "--config")?);
            }
            Some("--database") => {
                reject_display_combination(display.as_ref())?;
                if invocation.database_path.is_some() {
                    return Err(error("--database may be specified only once"));
                }
                invocation.database_path = Some(read_path(&mut args, "--database")?);
            }
            Some("--help" | "-h") => {
                if display.is_some()
                    || invocation.config_path.is_some()
                    || invocation.database_path.is_some()
                    || args.peek().is_some()
                {
                    return Err(error("--help cannot be combined with other arguments"));
                }
                display = Some(GuiParseOutcome::Help(gui_help().to_owned()));
            }
            Some("--version" | "-V") => {
                if display.is_some()
                    || invocation.config_path.is_some()
                    || invocation.database_path.is_some()
                    || args.peek().is_some()
                {
                    return Err(error("--version cannot be combined with other arguments"));
                }
                display = Some(GuiParseOutcome::Version(format!(
                    "conman {}",
                    cm_build_info::version()
                )));
            }
            Some(value) if value.starts_with('-') => {
                return Err(error(format!("unknown option `{}`", safe_token(&argument))));
            }
            _ => {
                return Err(error(format!(
                    "unexpected positional argument `{}`",
                    safe_token(&argument)
                )));
            }
        }
    }

    Ok(display.unwrap_or(GuiParseOutcome::Run(invocation)))
}

/// Static GUI usage text; does not write to a console.
#[must_use]
pub const fn gui_help() -> &'static str {
    "Connection Manager\n\n\
Usage: conman [--config PATH] [--database PATH]\n\n\
Options:\n  \
--config PATH    Use an alternate conman.ini file.\n  \
--database PATH  Use an alternate SQLite database.\n  \
-h, --help       Show this help and exit.\n  \
-V, --version    Show the version and exit."
}

fn read_path<I>(
    args: &mut std::iter::Peekable<I>,
    option: &str,
) -> Result<PathBuf, GuiArgumentError>
where
    I: Iterator<Item = OsString>,
{
    let Some(value) = args.next() else {
        return Err(error(format!("{option} requires a path")));
    };
    if value.is_empty()
        || value == OsStr::new("-")
        || value.to_str().is_some_and(|text| text.starts_with('-'))
    {
        return Err(error(format!("{option} requires a path")));
    }
    Ok(PathBuf::from(value))
}

fn reject_display_combination(display: Option<&GuiParseOutcome>) -> Result<(), GuiArgumentError> {
    match display {
        Some(GuiParseOutcome::Help(_)) => {
            Err(error("--help cannot be combined with other arguments"))
        }
        Some(GuiParseOutcome::Version(_)) => {
            Err(error("--version cannot be combined with other arguments"))
        }
        Some(GuiParseOutcome::Run(_)) | None => Ok(()),
    }
}

fn error(message: impl Into<String>) -> GuiArgumentError {
    GuiArgumentError {
        message: message.into(),
    }
}

fn safe_token(token: &OsStr) -> String {
    neutralize_terminal_text(&token.to_string_lossy())
}

/// Neutralize terminal-control and bidirectional-display characters in text
/// that is about to be presented as a diagnostic.
///
/// This deliberately leaves ordinary printable Unicode untouched while
/// replacing C0/C1 controls (including ESC, which starts OSC and CSI control
/// sequences) and bidi embedding/isolate controls. Callers should apply it
/// only to untrusted fragments; trusted formatting such as help-text newlines
/// should be added afterward.
#[must_use]
pub fn neutralize_terminal_text(input: &str) -> String {
    input
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<GuiParseOutcome, GuiArgumentError> {
        parse_gui_args(args.iter().copied())
    }

    #[test]
    fn empty_and_combined_overrides_produce_run_invocations() {
        assert_eq!(
            parse(&[]).unwrap(),
            GuiParseOutcome::Run(GuiInvocation::default())
        );
        assert_eq!(
            parse(&[
                "--database",
                "alternate.sqlite",
                "--config",
                "alternate.conman",
            ])
            .unwrap(),
            GuiParseOutcome::Run(GuiInvocation {
                config_path: Some(PathBuf::from("alternate.conman")),
                database_path: Some(PathBuf::from("alternate.sqlite")),
            })
        );
    }

    #[test]
    fn help_and_version_are_owned_effect_free_outcomes() {
        assert_eq!(
            parse(&["-h"]).unwrap(),
            GuiParseOutcome::Help(gui_help().to_owned())
        );
        assert_eq!(
            parse(&["--version"]).unwrap(),
            GuiParseOutcome::Version(format!("conman {}", cm_build_info::version()))
        );
    }

    #[test]
    fn unknown_positionals_duplicates_and_mixed_display_requests_fail() {
        for args in [
            vec!["saved-connection"],
            vec!["--unknown"],
            vec!["--config", "a", "--config", "b"],
            vec!["--database", "a", "--database", "b"],
            vec!["--help", "--config", "a"],
            vec!["--database", "a", "-V"],
        ] {
            let error = parse(&args).unwrap_err();
            assert_eq!(error.exit_code(), 2);
            assert!(error.render().contains("Usage: conman"));
        }
    }

    #[test]
    fn missing_and_stdio_paths_are_rejected() {
        for args in [
            vec!["--config"],
            vec!["--database"],
            vec!["--config", "-"],
            vec!["--database", "--version"],
            vec!["--config", "--unknown"],
        ] {
            assert!(
                parse(&args)
                    .unwrap_err()
                    .message()
                    .contains("requires a path")
            );
        }
    }

    #[test]
    fn diagnostics_neutralize_terminal_controls() {
        let error = parse(&["bad\u{1b}\u{202e}"]).unwrap_err();
        assert!(!error.render().contains('\u{1b}'));
        assert!(!error.render().contains('\u{202e}'));
    }

    #[test]
    fn shared_diagnostic_sanitizer_neutralizes_c0_c1_osc_and_bidi() {
        let hostile = "safe\0\u{001b}]0;owned\u{0007}\u{0085}\u{202e}txt\u{2066}";
        let safe = neutralize_terminal_text(hostile);
        assert_eq!(safe, "safe��]0;owned���txt�");
        assert!(!safe.chars().any(char::is_control));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_paths_are_preserved() {
        use std::os::unix::ffi::OsStringExt as _;

        let path = OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]);
        let outcome = parse_gui_args([OsString::from("--config"), path.clone()]).unwrap();
        assert_eq!(
            outcome,
            GuiParseOutcome::Run(GuiInvocation {
                config_path: Some(PathBuf::from(path)),
                database_path: None,
            })
        );
    }
}
