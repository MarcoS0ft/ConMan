use std::path::PathBuf;

use cm_core::{Connection, ConnectionSettings};
use serde::Serialize;

/// Global output mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}

/// Global path and output overrides attached to every parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalOptions {
    pub config_path: Option<PathBuf>,
    pub database_path: Option<PathBuf>,
    pub format: OutputFormat,
}

/// Fully validated request emitted by the command-registration layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub global: GlobalOptions,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Connections(ConnectionsCommand),
    Config(ConfigCommand),
    Completion { shell: CompletionShell },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionsCommand {
    List,
    Show {
        id: i64,
    },
    Import {
        source: PathBuf,
        password_stdin: bool,
    },
    Export {
        destination: PathBuf,
        include_secrets: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigCommand {
    Path,
    Validate {
        source: Option<PathBuf>,
    },
    Import {
        source: PathBuf,
        acknowledge_automation: bool,
    },
    Export {
        destination: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

impl CompletionShell {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
}

/// Structured successful result returned by the dispatcher.
#[derive(Debug, Clone)]
pub struct Execution {
    pub payload: Payload,
    pub diagnostics: Vec<Diagnostic>,
}

impl Execution {
    pub fn new(payload: Payload) -> Self {
        Self {
            payload,
            diagnostics: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub enum Payload {
    Connections(Vec<ConnectionRow>),
    Connection(Connection),
    ImportSummary(ImportSummary),
    ExportSummary(ExportSummary),
    ConfigPath(PathBuf),
    ConfigValidation(ConfigValidation),
    ConfigTransfer(ConfigTransfer),
    CompletionScript(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConnectionRow {
    pub id: i64,
    pub name: String,
    pub kind: &'static str,
    pub host: String,
    pub port: Option<u16>,
    pub group_id: Option<i64>,
}

impl From<&Connection> for ConnectionRow {
    fn from(connection: &Connection) -> Self {
        let (host, port) = match &connection.settings {
            ConnectionSettings::Rdp(settings) => (settings.host.clone(), Some(settings.port)),
            ConnectionSettings::Ssh(settings) => (settings.host.clone(), Some(settings.port)),
            ConnectionSettings::Telnet(settings) => (settings.host.clone(), Some(settings.port)),
            ConnectionSettings::Local(_) => (String::new(), None),
        };
        let kind = match connection.kind {
            cm_core::ConnectionKind::Rdp => "rdp",
            cm_core::ConnectionKind::Ssh => "ssh",
            cm_core::ConnectionKind::Telnet => "telnet",
            cm_core::ConnectionKind::LocalTerminal => "local",
        };
        Self {
            id: connection.id.get(),
            name: connection.name.clone(),
            kind,
            host,
            port,
            group_id: connection.group_id.map(cm_core::GroupId::get),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportSummary {
    pub credential_folders: usize,
    pub credentials: usize,
    pub groups: usize,
    pub connections: usize,
    pub secrets: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportSummary {
    pub destination: PathBuf,
    pub bytes: usize,
    pub included_secrets: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigValidation {
    pub path: PathBuf,
    pub valid: bool,
    pub warnings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigTransfer {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub bytes: usize,
}
