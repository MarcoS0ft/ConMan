//! Fatal GUI-startup error classification, message construction, and presentation.

use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupFailureKind {
    PathResolution,
    InstanceGuard,
    ConfigurationPath,
    ConfigurationRead,
    DatabasePath,
    DatabaseOpen,
    ApplicationInitialization,
    UiRuntime,
}

impl StartupFailureKind {
    fn summary(self) -> &'static str {
        match self {
            Self::PathResolution => "ConMan could not determine where its files are stored.",
            Self::InstanceGuard => "ConMan could not safely establish this application instance.",
            Self::ConfigurationPath => "ConMan could not prepare its configuration file.",
            Self::ConfigurationRead => "ConMan could not read its configuration file.",
            Self::DatabasePath => "ConMan could not prepare its connection database.",
            Self::DatabaseOpen => "ConMan could not open or upgrade its connection database.",
            Self::ApplicationInitialization => "ConMan could not initialize the application.",
            Self::UiRuntime => "ConMan could not initialize or run its graphical interface.",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StartupLocations {
    pub config_path: Option<PathBuf>,
    pub database_path: Option<PathBuf>,
    pub log_path: Option<PathBuf>,
}

impl StartupLocations {
    pub(crate) fn discovered(config_path: Option<PathBuf>, database_path: Option<PathBuf>) -> Self {
        Self {
            config_path,
            database_path,
            log_path: cm_platform::app_log_dir().ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupErrorMessage {
    pub kind: StartupFailureKind,
    pub title: String,
    pub body: String,
}

impl StartupErrorMessage {
    pub(crate) fn build(
        kind: StartupFailureKind,
        technical_detail: impl std::fmt::Display,
        locations: StartupLocations,
    ) -> Self {
        let detail = sanitize(&technical_detail.to_string());
        let mut paths = Vec::new();
        if let Some(path) = locations.config_path {
            paths.push(format!(
                "Configuration: {}",
                sanitize(&path.to_string_lossy())
            ));
        }
        if let Some(path) = locations.database_path {
            paths.push(format!("Database: {}", sanitize(&path.to_string_lossy())));
        }
        if let Some(path) = locations.log_path {
            paths.push(format!("Logs: {}", sanitize(&path.to_string_lossy())));
        }
        let path_section = if paths.is_empty() {
            "Paths were not available.".to_owned()
        } else {
            paths.join("\n")
        };
        Self {
            kind,
            title: "Connection Manager — Startup Error".to_owned(),
            body: format!(
                "{}\n\nTechnical details:\n{}\n\nAvailable paths:\n{}",
                kind.summary(),
                detail,
                path_section
            ),
        }
    }
}

fn sanitize(value: &str) -> String {
    cm_cli::neutralize_terminal_text(value)
}

pub(crate) trait StartupErrorPresenter {
    fn present(&self, message: &StartupErrorMessage, logging_available: bool);
}

pub(crate) struct NativeStartupErrorPresenter;

impl StartupErrorPresenter for NativeStartupErrorPresenter {
    fn present(&self, message: &StartupErrorMessage, logging_available: bool) {
        // Fatal pre-logging paths initialize the normal logging subsystem
        // locally and retain its worker guard through the blocking dialog.
        // This branch exits immediately afterward, so the renderer/agent env
        // ordering constraints for continuing startup no longer apply.
        let _fatal_logging_guard = (!logging_available).then(crate::logging::init);
        tracing::error!(kind = ?message.kind, detail = %message.body, "fatal startup failure");
        // Keep stderr as a fallback even after logging initialization: the
        // subscriber install is deliberately best-effort and may be rejected
        // when an embedding process already owns the global subscriber.
        let _ = cm_platform::write_stderr_line(&format!("fatal: {}", message.body));
        let _ = rfd::MessageDialog::new()
            .set_title(&message.title)
            .set_description(&message.body)
            .set_level(rfd::MessageLevel::Error)
            .set_buttons(rfd::MessageButtons::Ok)
            .show();
    }
}

pub(crate) fn present_fatal(
    presenter: &dyn StartupErrorPresenter,
    kind: StartupFailureKind,
    detail: impl std::fmt::Display,
    locations: StartupLocations,
    logging_available: bool,
) -> ExitCode {
    let message = StartupErrorMessage::build(kind, detail, locations);
    presenter.present(&message, logging_available);
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct RecordingPresenter(RefCell<Vec<(StartupErrorMessage, bool)>>);

    impl StartupErrorPresenter for RecordingPresenter {
        fn present(&self, message: &StartupErrorMessage, logging_available: bool) {
            self.0
                .borrow_mut()
                .push((message.clone(), logging_available));
        }
    }

    #[test]
    fn every_classification_has_a_specific_human_summary() {
        for (kind, expected) in [
            (StartupFailureKind::PathResolution, "determine where"),
            (StartupFailureKind::InstanceGuard, "safely establish"),
            (
                StartupFailureKind::ConfigurationPath,
                "prepare its configuration",
            ),
            (
                StartupFailureKind::ConfigurationRead,
                "read its configuration",
            ),
            (
                StartupFailureKind::DatabasePath,
                "prepare its connection database",
            ),
            (StartupFailureKind::DatabaseOpen, "open or upgrade"),
            (StartupFailureKind::ApplicationInitialization, "initialize"),
            (StartupFailureKind::UiRuntime, "graphical interface"),
        ] {
            assert!(kind.summary().contains(expected), "{kind:?}");
        }
    }

    #[test]
    fn message_contains_sanitized_detail_and_available_paths() {
        let message = StartupErrorMessage::build(
            StartupFailureKind::DatabaseOpen,
            "SQLite failed\u{1b}]0;owned\u{7}\u{202e}",
            StartupLocations {
                config_path: Some(PathBuf::from("config\nowned.conman")),
                database_path: Some(PathBuf::from("connections.sqlite")),
                log_path: Some(PathBuf::from("logs/conman.log")),
            },
        );
        assert!(message.body.contains("Technical details:"));
        assert!(message.body.contains("SQLite failed�]0;owned��"));
        assert!(message.body.contains("Configuration: config�owned.conman"));
        assert!(message.body.contains("Database: connections.sqlite"));
        assert!(message.body.contains("Logs: logs/conman.log"));
        assert!(!message.body.contains('\u{1b}'));
        assert!(!message.body.contains('\u{202e}'));
    }

    #[test]
    fn injected_presenter_receives_logging_state_without_opening_a_dialog() {
        let presenter = RecordingPresenter::default();
        assert_eq!(
            present_fatal(
                &presenter,
                StartupFailureKind::ApplicationInitialization,
                "initialization failed",
                StartupLocations::default(),
                true,
            ),
            ExitCode::FAILURE
        );
        let calls = presenter.0.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1);
        assert_eq!(
            calls[0].0.kind,
            StartupFailureKind::ApplicationInitialization
        );
    }
}
