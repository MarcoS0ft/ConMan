use std::path::Path;

use rich_rs::{Column, Console, ConsoleOptions, Row, Table, Text};
use serde::Serialize;

use crate::error::CliError;
use crate::types::{
    ConfigTransfer, ConfigValidation, ConnectionRow, DiagnosticLevel, Execution, ExportSummary,
    ImportSummary, OutputFormat, Payload,
};

/// Fully separated process output. Callers route fields to their matching
/// streams; JSON and shell-script payloads never receive decoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedOutput {
    pub stdout: String,
    pub stderr: String,
}

pub fn render(execution: Execution, format: OutputFormat) -> Result<RenderedOutput, CliError> {
    let stdout = match execution.payload {
        Payload::CompletionScript(script) => ensure_newline(script),
        payload if format == OutputFormat::Json => render_json(&payload)?,
        payload => render_table(payload)?,
    };
    let stderr = execution
        .diagnostics
        .into_iter()
        .map(|diagnostic| render_diagnostic(&diagnostic))
        .collect();
    Ok(RenderedOutput { stdout, stderr })
}

pub(crate) fn render_error(error: &CliError) -> String {
    neutralize(&error.to_string())
}

pub(crate) fn render_diagnostic(diagnostic: &crate::types::Diagnostic) -> String {
    let prefix = match diagnostic.level {
        DiagnosticLevel::Warning => "warning",
        DiagnosticLevel::Info => "info",
    };
    format!("{prefix}: {}\n", neutralize(&diagnostic.message))
}

fn render_json(payload: &Payload) -> Result<String, CliError> {
    let mut value = match payload {
        Payload::Connections(rows) => serde_json::to_value(rows),
        Payload::Connection(connection) => serde_json::to_value(connection),
        Payload::ImportSummary(summary) => serde_json::to_value(summary),
        Payload::ExportSummary(summary) => serde_json::to_value(summary),
        Payload::ConfigPath(path) => serde_json::to_value(PathOutput { path }),
        Payload::ConfigValidation(summary) => serde_json::to_value(summary),
        Payload::ConfigTransfer(summary) => serde_json::to_value(summary),
        Payload::CompletionScript(_) => unreachable!("handled before JSON rendering"),
    }
    .map_err(|error| CliError::Output(error.to_string()))?;
    neutralize_json(&mut value);
    let json = serde_json::to_string_pretty(&value)
        .map_err(|error| CliError::Output(error.to_string()))?;
    Ok(format!("{json}\n"))
}

fn neutralize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = neutralize(text),
        serde_json::Value::Array(items) => {
            for item in items {
                neutralize_json(item);
            }
        }
        serde_json::Value::Object(fields) => {
            for value in fields.values_mut() {
                neutralize_json(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

#[derive(Serialize)]
struct PathOutput<'a> {
    path: &'a Path,
}

fn render_table(payload: Payload) -> Result<String, CliError> {
    match payload {
        Payload::Connections(rows) => connections_table(&rows),
        Payload::Connection(connection) => {
            let row = ConnectionRow::from(&connection);
            key_value_table(&[
                ("ID", row.id.to_string()),
                ("Name", row.name),
                ("Kind", row.kind.to_owned()),
                ("Host", row.host),
                (
                    "Port",
                    row.port.map_or_else(String::new, |port| port.to_string()),
                ),
                (
                    "Group ID",
                    row.group_id.map_or_else(String::new, |id| id.to_string()),
                ),
            ])
        }
        Payload::ImportSummary(summary) => import_summary_table(&summary),
        Payload::ExportSummary(summary) => export_summary_table(&summary),
        Payload::ConfigPath(path) => Ok(format!("{}\n", neutralize(&path.display().to_string()))),
        Payload::ConfigValidation(summary) => config_validation_table(&summary),
        Payload::ConfigTransfer(summary) => config_transfer_table(&summary),
        Payload::CompletionScript(script) => Ok(ensure_newline(script)),
    }
}

fn connections_table(rows: &[ConnectionRow]) -> Result<String, CliError> {
    let mut table = Table::new();
    for heading in ["ID", "NAME", "KIND", "HOST", "PORT", "GROUP"] {
        table.add_column(Column::with_header_str(heading));
    }
    for item in rows {
        table.add_row(Row::new(vec![
            cell(item.id),
            cell(&item.name),
            cell(item.kind),
            cell(&item.host),
            cell(item.port.map_or_else(String::new, |port| port.to_string())),
            cell(item.group_id.map_or_else(String::new, |id| id.to_string())),
        ]));
    }
    capture_table(&table)
}

fn key_value_table(rows: &[(impl AsRef<str>, String)]) -> Result<String, CliError> {
    let mut table = Table::new().with_show_header(false);
    table.add_column(Column::new());
    table.add_column(Column::new());
    for (key, value) in rows {
        table.add_row(Row::new(vec![cell(key.as_ref()), cell(value)]));
    }
    capture_table(&table)
}

fn import_summary_table(summary: &ImportSummary) -> Result<String, CliError> {
    key_value_table(&[
        ("Credential folders", summary.credential_folders.to_string()),
        ("Credentials", summary.credentials.to_string()),
        ("Groups", summary.groups.to_string()),
        ("Connections", summary.connections.to_string()),
        ("Secrets", summary.secrets.to_string()),
        ("Warnings", summary.warnings.to_string()),
    ])
}

fn export_summary_table(summary: &ExportSummary) -> Result<String, CliError> {
    key_value_table(&[
        ("Destination", summary.destination.display().to_string()),
        ("Bytes", summary.bytes.to_string()),
        ("Secrets included", summary.included_secrets.to_string()),
    ])
}

fn config_validation_table(summary: &ConfigValidation) -> Result<String, CliError> {
    key_value_table(&[
        ("Path", summary.path.display().to_string()),
        ("Valid", summary.valid.to_string()),
        ("Warnings", summary.warnings.to_string()),
    ])
}

fn config_transfer_table(summary: &ConfigTransfer) -> Result<String, CliError> {
    key_value_table(&[
        ("Source", summary.source.display().to_string()),
        ("Destination", summary.destination.display().to_string()),
        ("Bytes", summary.bytes.to_string()),
    ])
}

fn capture_table(table: &Table) -> Result<String, CliError> {
    let mut console = Console::capture_with_options(ConsoleOptions {
        is_terminal: false,
        color_system: None,
        ..ConsoleOptions::default()
    });
    console
        .print(table, None, None, None, false, "\n")
        .map_err(|error| CliError::Output(error.to_string()))?;
    Ok(console.get_captured())
}

fn cell(value: impl ToString) -> Box<Text> {
    Box::new(Text::plain(neutralize(&value.to_string())))
}

pub(crate) fn neutralize(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        if character == '\n' {
            output.push_str("\\n");
        } else if character == '\r' {
            output.push_str("\\r");
        } else if character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            output.push('\u{fffd}');
        } else {
            output.push(character);
        }
    }
    output
}

fn ensure_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Diagnostic, DiagnosticLevel};

    #[test]
    fn json_stdout_is_valid_and_diagnostics_stay_on_stderr() {
        let execution = Execution {
            payload: Payload::Connections(vec![ConnectionRow {
                id: 1,
                name: "host".to_owned(),
                kind: "ssh",
                host: "example.test".to_owned(),
                port: Some(22),
                group_id: None,
            }]),
            diagnostics: vec![Diagnostic {
                level: DiagnosticLevel::Warning,
                message: "careful".to_owned(),
            }],
        };
        let output = render(execution, OutputFormat::Json).unwrap();
        serde_json::from_str::<serde_json::Value>(&output.stdout).unwrap();
        assert!(!output.stdout.contains("warning"));
        assert_eq!(output.stderr, "warning: careful\n");
    }

    #[test]
    fn table_cells_neutralize_terminal_controls_and_bidi() {
        let output = render(
            Execution::new(Payload::Connections(vec![ConnectionRow {
                id: 1,
                name: "bad\u{1b}[31m\u{202e}".to_owned(),
                kind: "ssh",
                host: String::new(),
                port: None,
                group_id: None,
            }])),
            OutputFormat::Table,
        )
        .unwrap();
        assert!(!output.stdout.contains('\u{1b}'));
        assert!(!output.stdout.contains('\u{202e}'));
    }

    #[test]
    fn completion_script_is_raw_in_json_mode() {
        let output = render(
            Execution::new(Payload::CompletionScript("complete script".to_owned())),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(output.stdout, "complete script\n");
    }
}
