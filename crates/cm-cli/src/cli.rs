use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use click::completion::get_completion_class;
use click::types::Choice;
use click::{Argument, ClickError, ClickOption, Command as ClickCommand, Group};
use rich_click_rs::{RichHelpConfig, main_rich_group_with_errors};

use crate::render::neutralize;
use crate::types::{
    Command, CompletionShell, ConfigCommand, ConnectionsCommand, GlobalOptions, Invocation,
    OutputFormat,
};

type InvocationSlot = Arc<Mutex<Option<Invocation>>>;

/// Registration-only command tree. Callbacks construct a typed [`Invocation`]
/// and never perform filesystem, database, keyring, environment, or rendering
/// effects.
#[derive(Debug)]
pub struct CliParser {
    command: Group,
    slot: InvocationSlot,
}

impl CliParser {
    #[must_use]
    pub fn new() -> Self {
        let slot = Arc::new(Mutex::new(None));
        let command = root_group(&slot);
        Self { command, slot }
    }

    /// Parse explicit arguments. Help and version requests return `Ok(None)`
    /// after Click has emitted their output.
    pub fn parse(&self, args: Vec<String>) -> Result<Option<Invocation>, ClickError> {
        self.clear_slot();
        match click::CommandLike::main(&self.command, sanitize_args(args)) {
            Ok(()) | Err(ClickError::Exit { code: 0 }) => Ok(self.take()),
            Err(error) => Err(error),
        }
    }

    /// Parse with rich help and error presentation.
    pub fn parse_rich(&self, args: Vec<String>) -> Result<Option<Invocation>, ClickError> {
        self.clear_slot();
        main_rich_group_with_errors(
            &self.command,
            sanitize_args(args),
            &RichHelpConfig::default(),
        )?;
        Ok(self.take())
    }

    fn clear_slot(&self) {
        *self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn take(&self) -> Option<Invocation> {
        self.slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

fn sanitize_args(args: Vec<String>) -> Vec<String> {
    args.into_iter()
        .map(|argument| neutralize(&argument))
        .collect()
}

impl Default for CliParser {
    fn default() -> Self {
        Self::new()
    }
}

fn root_group(slot: &InvocationSlot) -> Group {
    Group::new("conmanctl")
        .help("Scriptable connection and configuration management for Connection Manager.")
        // Keep the eager version option first. rich-click-rs 1.0.2's version
        // detector stops at the first ordinary metavar-bearing option.
        .option(
            ClickOption::new(&["--version", "-V"])
                .help("Show the version and exit.")
                .flag("true")
                .eager()
                .metavar(&format!(
                    "__click_version__:conmanctl {}",
                    cm_build_info::version()
                ))
                .build(),
        )
        .option(path_option("--config", "Use an alternate conman.ini file."))
        .option(path_option(
            "--database",
            "Use an alternate SQLite database.",
        ))
        .option(
            ClickOption::new(&["--format"])
                .help("Output format for successful data.")
                .type_(Choice::new(["table", "json"]))
                .default("table")
                .show_default()
                .build(),
        )
        .command(connections_group(slot))
        .command(config_group(slot))
        .command(completion_command(slot))
        .build()
}

fn connections_group(slot: &InvocationSlot) -> Group {
    Group::new("connections")
        .help("List, inspect, import, and export saved connections.")
        .command(leaf("list", "List saved connections.", slot, |_| {
            Ok(Command::Connections(ConnectionsCommand::List))
        }))
        .command(
            ClickCommand::new("show")
                .help("Show one saved connection by numeric ID.")
                .argument(Argument::new("id").help("Positive connection ID.").build())
                .callback(callback(slot, |ctx| {
                    let raw = required(ctx, "id")?;
                    let id = raw.parse::<i64>().map_err(|_| {
                        ClickError::usage("connection ID must be a positive integer")
                    })?;
                    if id <= 0 {
                        return Err(ClickError::usage(
                            "connection ID must be a positive integer",
                        ));
                    }
                    Ok(Command::Connections(ConnectionsCommand::Show { id }))
                }))
                .build(),
        )
        .command(
            ClickCommand::new("import")
                .help("Import connections from .json, .csv, .rjson, or .xml.")
                .argument(path_argument("source", "Named source file."))
                .option(
                    ClickOption::new(&["--password-stdin"])
                        .help("Read an mRemoteNG decryption password from standard input.")
                        .flag("true")
                        .build(),
                )
                .callback(callback(slot, |ctx| {
                    Ok(Command::Connections(ConnectionsCommand::Import {
                        source: named_path(required(ctx, "source")?, "source")?,
                        password_stdin: flag(ctx, "password_stdin"),
                    }))
                }))
                .build(),
        )
        .command(
            ClickCommand::new("export")
                .help("Export connections to a new JSON file; never overwrites a destination.")
                .argument(path_argument("destination", "Named destination file."))
                .option(
                    ClickOption::new(&["--include-secrets"])
                        .help("Include keychain secrets in the named output file.")
                        .flag("true")
                        .build(),
                )
                .callback(callback(slot, |ctx| {
                    Ok(Command::Connections(ConnectionsCommand::Export {
                        destination: named_path(required(ctx, "destination")?, "destination")?,
                        include_secrets: flag(ctx, "include_secrets"),
                    }))
                }))
                .build(),
        )
        .build()
}

fn config_group(slot: &InvocationSlot) -> Group {
    Group::new("config")
        .help("Inspect, validate, import, and export the editable configuration.")
        .command(leaf(
            "path",
            "Print the selected configuration path.",
            slot,
            |_| Ok(Command::Config(ConfigCommand::Path)),
        ))
        .command(
            ClickCommand::new("validate")
                .help("Validate a source file, or the selected configuration when omitted.")
                .argument(
                    Argument::new("source")
                        .help("Optional named config file.")
                        .default("")
                        .build(),
                )
                .callback(callback(slot, |ctx| {
                    let source = optional(ctx, "source")
                        .filter(|value| !value.is_empty())
                        .map(|value| named_path(value, "source"))
                        .transpose()?;
                    Ok(Command::Config(ConfigCommand::Validate { source }))
                }))
                .build(),
        )
        .command(
            ClickCommand::new("import")
                .help(
                    "Validate and atomically replace the selected configuration. An imported \
                     file can enable or broaden automation access; such files require --yes.",
                )
                .argument(path_argument("source", "Named source config file."))
                .option(
                    ClickOption::new(&["--yes"])
                        .help("Acknowledge enabling or broadening automation access when present.")
                        .flag("true")
                        .build(),
                )
                .callback(callback(slot, |ctx| {
                    Ok(Command::Config(ConfigCommand::Import {
                        source: named_path(required(ctx, "source")?, "source")?,
                        acknowledge_automation: flag(ctx, "yes"),
                    }))
                }))
                .build(),
        )
        .command(
            ClickCommand::new("export")
                .help("Copy the selected configuration to a new named file.")
                .argument(path_argument(
                    "destination",
                    "Named destination config file.",
                ))
                .callback(callback(slot, |ctx| {
                    Ok(Command::Config(ConfigCommand::Export {
                        destination: named_path(required(ctx, "destination")?, "destination")?,
                    }))
                }))
                .build(),
        )
        .build()
}

fn completion_command(slot: &InvocationSlot) -> ClickCommand {
    ClickCommand::new("completion")
        .help("Generate a shell completion script.")
        .argument(
            Argument::new("shell")
                .help("Target shell.")
                .type_(Choice::new(["bash", "zsh", "fish"]))
                .build(),
        )
        .callback(callback(slot, |ctx| {
            let shell = match required(ctx, "shell")? {
                "bash" => CompletionShell::Bash,
                "zsh" => CompletionShell::Zsh,
                "fish" => CompletionShell::Fish,
                _ => return Err(ClickError::usage("unsupported completion shell")),
            };
            // Keep generation support coupled to the registered Click shell
            // adapters, while the dispatcher owns the actual output effect.
            if get_completion_class(shell.as_str()).is_none() {
                return Err(ClickError::usage("unsupported completion shell"));
            }
            Ok(Command::Completion { shell })
        }))
        .build()
}

fn leaf<F>(name: &str, help: &str, slot: &InvocationSlot, make: F) -> ClickCommand
where
    F: Fn(&click::Context) -> Result<Command, ClickError> + Send + Sync + 'static,
{
    ClickCommand::new(name)
        .help(help)
        .callback(callback(slot, make))
        .build()
}

fn callback<F>(
    slot: &InvocationSlot,
    make: F,
) -> impl Fn(&click::Context) -> Result<(), ClickError> + Send + Sync + 'static
where
    F: Fn(&click::Context) -> Result<Command, ClickError> + Send + Sync + 'static,
{
    let slot = Arc::clone(slot);
    move |ctx| {
        let invocation = Invocation {
            global: global_options(ctx.find_root())?,
            command: make(ctx)?,
        };
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(invocation);
        Ok(())
    }
}

fn global_options(root: &click::Context) -> Result<GlobalOptions, ClickError> {
    let format = match optional(root, "format").unwrap_or("table") {
        "table" => OutputFormat::Table,
        "json" => OutputFormat::Json,
        _ => return Err(ClickError::usage("format must be table or json")),
    };
    Ok(GlobalOptions {
        config_path: optional(root, "config")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        database_path: optional(root, "database")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        format,
    })
}

fn required<'a>(ctx: &'a click::Context, name: &str) -> Result<&'a str, ClickError> {
    optional(ctx, name).ok_or_else(|| ClickError::missing_argument(name.to_ascii_uppercase()))
}

fn optional<'a>(ctx: &'a click::Context, name: &str) -> Option<&'a str> {
    ctx.get_param::<String>(name).map(String::as_str)
}

fn flag(ctx: &click::Context, name: &str) -> bool {
    optional(ctx, name).is_some_and(|value| value == "true")
}

fn named_path(value: &str, label: &str) -> Result<PathBuf, ClickError> {
    if value.trim().is_empty() || value == "-" {
        return Err(ClickError::usage(format!(
            "{label} must be a named file path, not standard input/output"
        )));
    }
    Ok(PathBuf::from(value))
}

fn path_option(name: &'static str, help: &'static str) -> click::ClickOption {
    ClickOption::new(&[name]).help(help).metavar("PATH").build()
}

fn path_argument(name: &'static str, help: &'static str) -> click::Argument {
    Argument::new(name).help(help).metavar("PATH").build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_globals_into_typed_invocation() {
        let invocation = CliParser::new()
            .parse(args(&[
                "--config",
                "custom.conman",
                "--database",
                "other.sqlite",
                "--format",
                "json",
                "connections",
                "show",
                "42",
            ]))
            .unwrap()
            .unwrap();
        assert_eq!(invocation.global.format, OutputFormat::Json);
        assert_eq!(
            invocation.global.config_path,
            Some(PathBuf::from("custom.conman"))
        );
        assert_eq!(
            invocation.command,
            Command::Connections(ConnectionsCommand::Show { id: 42 })
        );
    }

    #[test]
    fn invalid_id_and_stdio_destination_fail_before_dispatch() {
        assert!(
            CliParser::new()
                .parse(args(&["connections", "show", "0"]))
                .is_err()
        );
        assert!(
            CliParser::new()
                .parse(args(&["connections", "export", "-"]))
                .is_err()
        );
    }

    #[test]
    fn password_has_no_argument_or_environment_option() {
        assert!(
            CliParser::new()
                .parse(args(&[
                    "connections",
                    "import",
                    "input.xml",
                    "--password",
                    "canary"
                ]))
                .is_err()
        );
        let invocation = CliParser::new()
            .parse(args(&[
                "connections",
                "import",
                "input.xml",
                "--password-stdin",
            ]))
            .unwrap()
            .unwrap();
        assert!(matches!(
            invocation.command,
            Command::Connections(ConnectionsCommand::Import {
                password_stdin: true,
                ..
            })
        ));
    }

    #[test]
    fn parser_errors_neutralize_control_and_bidi_tokens() {
        let hostile = "--unknown\u{1b}]8;;target\u{7}\u{9d}\u{202e}";
        let rendered = CliParser::new()
            .parse(args(&[hostile]))
            .unwrap_err()
            .to_string();
        for forbidden in ['\u{1b}', '\u{7}', '\u{9d}', '\u{202e}'] {
            assert!(!rendered.contains(forbidden), "{rendered:?}");
        }
    }

    #[test]
    fn every_command_group_has_help() {
        for command in [
            vec!["--help"],
            vec!["connections", "--help"],
            vec!["config", "--help"],
            vec!["completion", "--help"],
        ] {
            assert!(CliParser::new().parse(args(&command)).is_ok());
        }
    }
}
