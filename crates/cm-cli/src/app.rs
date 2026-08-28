use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use click::completion::get_completion_class;
use cm_core::{AppConfigStore as _, ConnectionId, ConnectionRepository as _, Secret, SettingKey};
use cm_platform::{ConfigDiagnosticLevel, ConfigDocument, TextConfigStore, read_config_file};
use cm_secrets::{KeyringStore, initialize_native_keyring};
use cm_storage::import::{import_from_path, import_from_path_with_password};
use cm_storage::{ExportOptions, ImportExportError, SqliteRepository, export_to_json};

use crate::error::CliError;
use crate::types::{
    Command, ConfigCommand, ConfigTransfer, ConfigValidation, ConnectionRow, ConnectionsCommand,
    Diagnostic, DiagnosticLevel, Execution, ExportSummary, ImportSummary, Invocation, Payload,
};

/// Injected source for encrypted-import passwords. Implementations must not
/// log, cache, or expose the returned value through `Debug`.
pub trait PasswordInput {
    fn read_password(&mut self) -> Result<Password, CliError>;
}

/// Immediate diagnostic boundary used when a warning must be presented before
/// a following mutation. Implementations must return only after the diagnostic
/// has been durably handed to the selected output stream.
pub trait DiagnosticSink {
    fn emit(&mut self, diagnostic: &Diagnostic) -> Result<(), CliError>;
}

impl<F> DiagnosticSink for F
where
    F: FnMut(&Diagnostic) -> Result<(), CliError>,
{
    fn emit(&mut self, diagnostic: &Diagnostic) -> Result<(), CliError> {
        self(diagnostic)
    }
}

/// Password read from standard input. No command argument or environment
/// variable is accepted for this value.
#[derive(Debug, Default)]
pub struct StdinPasswordInput;

impl PasswordInput for StdinPasswordInput {
    fn read_password(&mut self) -> Result<Password, CliError> {
        const MAX_PASSWORD_BYTES: u64 = 64 * 1024;
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_PASSWORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                CliError::Input(format!("could not read password from stdin: {error}"))
            })?;
        if bytes.len() as u64 > MAX_PASSWORD_BYTES {
            return Err(CliError::Input(format!(
                "password input exceeds {MAX_PASSWORD_BYTES} bytes"
            )));
        }
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        if bytes.is_empty() {
            return Err(CliError::Input("password input was empty".to_owned()));
        }
        if std::str::from_utf8(&bytes).is_err() {
            return Err(CliError::Input(
                "password input must be valid UTF-8".to_owned(),
            ));
        }
        Ok(Password(Secret::new(bytes)))
    }
}

/// Sensitive input with deliberately redacted formatting.
pub struct Password(Secret);

impl Password {
    fn expose(&self) -> &str {
        std::str::from_utf8(self.0.expose()).expect("password originated as valid UTF-8")
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Password(<redacted>)")
    }
}

/// Central effect boundary for a typed invocation.
pub fn dispatch(
    invocation: Invocation,
    password_input: &mut dyn PasswordInput,
    diagnostic_sink: &mut dyn DiagnosticSink,
) -> Result<Execution, CliError> {
    match invocation.command {
        Command::Connections(command) => {
            dispatch_connections(&invocation.global, command, password_input)
        }
        Command::Config(command) => dispatch_config(&invocation.global, command, diagnostic_sink),
        Command::Completion { shell } => {
            let completer = get_completion_class(shell.as_str()).ok_or_else(|| {
                CliError::Usage(format!("unsupported completion shell {}", shell.as_str()))
            })?;
            Ok(Execution::new(Payload::CompletionScript(
                completer.get_source("conmanctl", "_CONMANCTL_COMPLETE"),
            )))
        }
    }
}

fn dispatch_connections(
    global: &crate::types::GlobalOptions,
    command: ConnectionsCommand,
    password_input: &mut dyn PasswordInput,
) -> Result<Execution, CliError> {
    let db_path = resolve_db_path(global.database_path.as_deref())?;
    match command {
        ConnectionsCommand::List => {
            let repository = open_repository(&db_path, None)?;
            let connections = repository
                .list_connections()
                .map_err(|error| CliError::Storage(error.to_string()))?;
            Ok(Execution::new(Payload::Connections(
                connections.iter().map(ConnectionRow::from).collect(),
            )))
        }
        ConnectionsCommand::Show { id } => {
            let repository = open_repository(&db_path, None)?;
            let connection = repository
                .get_connection(ConnectionId::new(id))
                .map_err(|error| CliError::Storage(error.to_string()))?
                .ok_or(CliError::NotFound(id))?;
            Ok(Execution::new(Payload::Connection(connection)))
        }
        ConnectionsCommand::Import {
            source,
            password_stdin,
        } => {
            initialize_native_keyring();
            let store = Arc::new(KeyringStore::new());
            let repository = open_repository(&db_path, Some(store.clone()))?;
            let result = import_from_path(&source, &repository, Some(store.as_ref()));
            let outcome = match result {
                Ok(outcome) => outcome,
                Err(ImportExportError::PasswordRequired) if password_stdin => {
                    let password = password_input.read_password()?;
                    import_from_path_with_password(
                        &source,
                        &repository,
                        Some(store.as_ref()),
                        password.expose(),
                    )
                    .map_err(import_error)?
                }
                Err(ImportExportError::PasswordRequired) => {
                    return Err(CliError::Input(
                        "the import is encrypted; retry with --password-stdin".to_owned(),
                    ));
                }
                Err(error) => return Err(import_error(error)),
            };
            let mut execution = Execution::new(Payload::ImportSummary(ImportSummary {
                credential_folders: outcome.stats.credential_folders_imported,
                credentials: outcome.stats.credentials_imported,
                groups: outcome.stats.groups_imported,
                connections: outcome.stats.connections_imported,
                secrets: outcome.stats.secrets_imported,
                warnings: outcome.warnings.len(),
            }));
            execution
                .diagnostics
                .extend(outcome.warnings.into_iter().map(|warning| Diagnostic {
                    level: DiagnosticLevel::Warning,
                    message: warning.message,
                }));
            if outcome.secrets_attempted > outcome.stats.secrets_imported {
                execution.diagnostics.push(Diagnostic {
                    level: DiagnosticLevel::Warning,
                    message: format!(
                        "{} secret(s) could not be persisted",
                        outcome
                            .secrets_attempted
                            .saturating_sub(outcome.stats.secrets_imported)
                    ),
                });
            }
            Ok(execution)
        }
        ConnectionsCommand::Export {
            destination,
            include_secrets,
        } => {
            let store = include_secrets.then(|| {
                initialize_native_keyring();
                Arc::new(KeyringStore::new())
            });
            let repository = open_repository(&db_path, store.clone())?;
            let outcome = export_to_json(
                &repository,
                &ExportOptions { include_secrets },
                store
                    .as_ref()
                    .map(|store| store.as_ref() as &dyn cm_core::CredentialStore),
            )
            .map_err(import_error)?;
            write_noclobber(&destination, outcome.json.as_bytes())?;
            let mut execution = Execution::new(Payload::ExportSummary(ExportSummary {
                destination,
                bytes: outcome.json.len(),
                included_secrets: include_secrets,
            }));
            if include_secrets {
                execution.diagnostics.push(Diagnostic {
                    level: DiagnosticLevel::Warning,
                    message: "the exported file contains plaintext credential material".to_owned(),
                });
            }
            Ok(execution)
        }
    }
}

fn dispatch_config(
    global: &crate::types::GlobalOptions,
    command: ConfigCommand,
    diagnostic_sink: &mut dyn DiagnosticSink,
) -> Result<Execution, CliError> {
    let config_path = resolve_config_path(global.config_path.as_deref())?;
    match command {
        ConfigCommand::Path => Ok(Execution::new(Payload::ConfigPath(config_path))),
        ConfigCommand::Validate { source } => {
            let (path, text) = match source {
                Some(path) => {
                    let text = fs::read_to_string(&path).map_err(|error| {
                        CliError::Filesystem(format!("could not read {}: {error}", path.display()))
                    })?;
                    (path, text)
                }
                None => {
                    let text = read_config_file(&config_path).map_err(config_error)?;
                    (config_path, text)
                }
            };
            let diagnostics = validate_config(&text)?;
            let warnings = diagnostics.len();
            let mut execution = Execution::new(Payload::ConfigValidation(ConfigValidation {
                path,
                valid: true,
                warnings,
            }));
            execution.diagnostics = diagnostics;
            Ok(execution)
        }
        ConfigCommand::Import {
            source,
            acknowledge_automation,
        } => {
            let text = fs::read_to_string(&source).map_err(|error| {
                CliError::Filesystem(format!("could not read {}: {error}", source.display()))
            })?;
            let diagnostics = validate_config(&text)?;
            let automation_sensitive = enables_automation(&text)?;
            if automation_sensitive && !acknowledge_automation {
                return Err(CliError::Usage(
                    "the imported configuration enables or broadens automation access; review \
                     it and retry with --yes to acknowledge this security-sensitive change"
                        .to_owned(),
                ));
            }
            if automation_sensitive {
                diagnostic_sink.emit(&Diagnostic {
                    level: DiagnosticLevel::Warning,
                    message: "this import will enable or broaden automation access".to_owned(),
                })?;
            }
            let store = TextConfigStore::new(&config_path);
            store.replace_document(&text).map_err(config_error)?;
            let mut execution = Execution::new(Payload::ConfigTransfer(ConfigTransfer {
                source,
                destination: config_path,
                bytes: text.len(),
            }));
            execution.diagnostics = diagnostics;
            Ok(execution)
        }
        ConfigCommand::Export { destination } => {
            let text = read_config_file(&config_path).map_err(config_error)?;
            write_noclobber(&destination, text.as_bytes())?;
            Ok(Execution::new(Payload::ConfigTransfer(ConfigTransfer {
                source: config_path,
                destination,
                bytes: text.len(),
            })))
        }
    }
}

fn validate_config(text: &str) -> Result<Vec<Diagnostic>, CliError> {
    let document = ConfigDocument::parse(text).map_err(|diagnostics| {
        let details = diagnostics
            .into_iter()
            .filter(|item| item.level == ConfigDiagnosticLevel::Error)
            .map(|item| format!("line {}: {}", item.line, item.message))
            .collect::<Vec<_>>()
            .join("; ");
        CliError::Config(details)
    })?;

    let mut diagnostics = document
        .diagnostics()
        .iter()
        .map(|item| Diagnostic {
            level: DiagnosticLevel::Warning,
            message: format!("line {}: {}", item.line, item.message),
        })
        .collect::<Vec<_>>();

    let final_lines = document
        .assignments()
        .map(|(line, key, _)| (key.to_owned(), line))
        .collect::<std::collections::HashMap<_, _>>();
    for (key, value) in document.effective_assignments() {
        let line = final_lines.get(&key).copied().unwrap_or(1);
        match key.parse::<SettingKey>() {
            Ok(key) => key
                .validate_value(&value)
                .map_err(|error| CliError::Config(format!("line {line}: {error}")))?,
            Err(()) => diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Warning,
                message: format!("line {line}: unknown configuration key `{key}` is preserved"),
            }),
        }
    }
    Ok(diagnostics)
}

fn enables_automation(text: &str) -> Result<bool, CliError> {
    let document = ConfigDocument::parse(text)
        .map_err(|_| CliError::Config("configuration contains syntax errors".to_owned()))?;
    Ok(
        document.effective_value("automation-enabled") == Some("true")
            || document
                .effective_value("automation-scopes")
                .is_some_and(|value| !value.trim().is_empty()),
    )
}

fn resolve_db_path(override_path: Option<&Path>) -> Result<PathBuf, CliError> {
    match override_path {
        Some(path) => {
            ensure_parent(path)?;
            Ok(path.to_path_buf())
        }
        None => cm_platform::app_db_path().map_err(|error| CliError::Filesystem(error.to_string())),
    }
}

fn resolve_config_path(override_path: Option<&Path>) -> Result<PathBuf, CliError> {
    match override_path {
        Some(path) => {
            ensure_parent(path)?;
            Ok(path.to_path_buf())
        }
        None => {
            cm_platform::app_config_path().map_err(|error| CliError::Filesystem(error.to_string()))
        }
    }
}

fn ensure_parent(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            CliError::Filesystem(format!("could not create {}: {error}", parent.display()))
        })?;
    }
    Ok(())
}

fn open_repository(
    path: &Path,
    credential_store: Option<Arc<KeyringStore>>,
) -> Result<SqliteRepository, CliError> {
    let repository =
        SqliteRepository::open(path).map_err(|error| CliError::Storage(error.to_string()))?;
    Ok(match credential_store {
        Some(store) => repository.with_credential_store(store),
        None => repository,
    })
}

fn write_noclobber(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(CliError::Filesystem(format!(
            "destination parent {} does not exist",
            parent.display()
        )));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Filesystem(format!("could not create temporary output: {error}"))
    })?;
    temporary.write_all(contents).map_err(|error| {
        CliError::Filesystem(format!("could not write temporary output: {error}"))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        CliError::Filesystem(format!("could not synchronize temporary output: {error}"))
    })?;
    temporary.persist_noclobber(path).map_err(|error| {
        CliError::Filesystem(format!(
            "refusing to overwrite {}: {}",
            path.display(),
            error.error
        ))
    })?;
    Ok(())
}

fn import_error(error: ImportExportError) -> CliError {
    CliError::ImportExport(error.to_string())
}

fn config_error(error: cm_core::AppConfigError) -> CliError {
    CliError::Config(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GlobalOptions, OutputFormat};
    use cm_core::{
        Connection, ConnectionId, ConnectionKind, ConnectionSettings, CredentialSource,
        LocalSettings,
    };
    use pretty_assertions::assert_eq;

    #[derive(Debug, Default)]
    struct NoPassword;

    impl PasswordInput for NoPassword {
        fn read_password(&mut self) -> Result<Password, CliError> {
            panic!("password input was not expected")
        }
    }

    fn dispatch(
        invocation: Invocation,
        password_input: &mut dyn PasswordInput,
    ) -> Result<Execution, CliError> {
        let mut diagnostic_sink = |_diagnostic: &Diagnostic| Ok(());
        super::dispatch(invocation, password_input, &mut diagnostic_sink)
    }

    fn globals(directory: &Path) -> GlobalOptions {
        GlobalOptions {
            config_path: Some(directory.join("config.conman")),
            database_path: Some(directory.join("conman.sqlite")),
            format: OutputFormat::Json,
        }
    }

    #[test]
    fn list_and_show_dispatch_against_headless_storage() {
        let directory = tempfile::tempdir().unwrap();
        let global = globals(directory.path());
        let repository = SqliteRepository::open(global.database_path.as_ref().unwrap()).unwrap();
        repository
            .upsert_connection(
                &Connection::new(
                    ConnectionId::UNSAVED,
                    None,
                    "local".to_owned(),
                    ConnectionKind::LocalTerminal,
                    ConnectionSettings::Local(LocalSettings::default()),
                    Some(CredentialSource::Prompt),
                    0,
                    0,
                    0,
                )
                .unwrap(),
            )
            .unwrap();
        drop(repository);

        let listed = dispatch(
            Invocation {
                global: global.clone(),
                command: Command::Connections(ConnectionsCommand::List),
            },
            &mut NoPassword,
        )
        .unwrap();
        let Payload::Connections(rows) = listed.payload else {
            panic!("wrong payload")
        };
        assert_eq!(rows.len(), 1);

        let shown = dispatch(
            Invocation {
                global,
                command: Command::Connections(ConnectionsCommand::Show { id: rows[0].id }),
            },
            &mut NoPassword,
        )
        .unwrap();
        assert!(matches!(shown.payload, Payload::Connection(_)));
    }

    #[test]
    fn config_validation_is_strict_but_preserves_unknown_keys() {
        let directory = tempfile::tempdir().unwrap();
        let global = globals(directory.path());
        fs::write(
            global.config_path.as_ref().unwrap(),
            "theme = dark\nfuture-key = yes\n",
        )
        .unwrap();
        let execution = dispatch(
            Invocation {
                global,
                command: Command::Config(ConfigCommand::Validate { source: None }),
            },
            &mut NoPassword,
        )
        .unwrap();
        assert_eq!(execution.diagnostics.len(), 1);
        assert!(execution.diagnostics[0].message.contains("future-key"));
    }

    #[test]
    fn exports_never_clobber_existing_destinations() {
        let directory = tempfile::tempdir().unwrap();
        let global = globals(directory.path());
        fs::write(global.config_path.as_ref().unwrap(), "theme = dark\n").unwrap();
        let destination = directory.path().join("saved.conman");
        fs::write(&destination, "keep me").unwrap();
        let error = dispatch(
            Invocation {
                global,
                command: Command::Config(ConfigCommand::Export {
                    destination: destination.clone(),
                }),
            },
            &mut NoPassword,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::Filesystem(_)));
        assert_eq!(fs::read_to_string(destination).unwrap(), "keep me");
    }

    #[test]
    fn connection_export_and_import_round_trip_through_named_files() {
        let directory = tempfile::tempdir().unwrap();
        let source_globals = globals(directory.path());
        let repository =
            SqliteRepository::open(source_globals.database_path.as_ref().unwrap()).unwrap();
        repository
            .upsert_connection(
                &Connection::new(
                    ConnectionId::UNSAVED,
                    None,
                    "round-trip".to_owned(),
                    ConnectionKind::LocalTerminal,
                    ConnectionSettings::Local(LocalSettings::default()),
                    Some(CredentialSource::Prompt),
                    0,
                    0,
                    0,
                )
                .unwrap(),
            )
            .unwrap();
        drop(repository);

        let destination = directory.path().join("connections.json");
        dispatch(
            Invocation {
                global: source_globals,
                command: Command::Connections(ConnectionsCommand::Export {
                    destination: destination.clone(),
                    include_secrets: false,
                }),
            },
            &mut NoPassword,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&destination).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "connection exports must be private");
        }

        let imported_globals = GlobalOptions {
            config_path: Some(directory.path().join("imported.conman")),
            database_path: Some(directory.path().join("imported.sqlite")),
            format: OutputFormat::Json,
        };
        let imported = dispatch(
            Invocation {
                global: imported_globals.clone(),
                command: Command::Connections(ConnectionsCommand::Import {
                    source: destination,
                    password_stdin: false,
                }),
            },
            &mut NoPassword,
        )
        .unwrap();
        let Payload::ImportSummary(summary) = imported.payload else {
            panic!("wrong payload")
        };
        assert_eq!(summary.connections, 1);
        let repository =
            SqliteRepository::open(imported_globals.database_path.as_ref().unwrap()).unwrap();
        assert_eq!(repository.list_connections().unwrap()[0].name, "round-trip");
    }

    #[test]
    fn config_import_requires_acknowledgement_and_warns_before_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let global = globals(directory.path());
        let selected = global.config_path.as_ref().unwrap().clone();
        let source = directory.path().join("incoming.conman");
        fs::write(&selected, "theme = dark\n").unwrap();
        fs::write(
            &source,
            "theme = light\nautomation-enabled = true\nautomation-scopes = read\n",
        )
        .unwrap();

        let refused = dispatch(
            Invocation {
                global: global.clone(),
                command: Command::Config(ConfigCommand::Import {
                    source: source.clone(),
                    acknowledge_automation: false,
                }),
            },
            &mut NoPassword,
        )
        .unwrap_err();
        assert!(matches!(refused, CliError::Usage(_)));
        assert_eq!(fs::read_to_string(&selected).unwrap(), "theme = dark\n");

        let mut warning_seen = false;
        let mut diagnostic_sink = |diagnostic: &Diagnostic| {
            assert!(diagnostic.message.contains("automation"));
            assert_eq!(fs::read_to_string(&selected).unwrap(), "theme = dark\n");
            warning_seen = true;
            Ok(())
        };
        super::dispatch(
            Invocation {
                global: global.clone(),
                command: Command::Config(ConfigCommand::Import {
                    source,
                    acknowledge_automation: true,
                }),
            },
            &mut NoPassword,
            &mut diagnostic_sink,
        )
        .unwrap();
        assert!(warning_seen);
        assert!(
            fs::read_to_string(selected)
                .unwrap()
                .contains("automation-enabled = true")
        );
    }

    #[test]
    fn password_debug_is_redacted() {
        let password = Password(Secret::from_string("canary-secret".to_owned()));
        assert_eq!(format!("{password:?}"), "Password(<redacted>)");
        assert!(!format!("{password:?}").contains("canary"));
    }
}
