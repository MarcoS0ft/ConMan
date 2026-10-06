//! Shared Slint consumer for the frozen `cm_core::application::Application` port.
//!
//! This module contains only UI-owned state and port commands. It does not
//! name repositories, machine configuration, sessions, or platform adapters.
use std::{cell::RefCell, rc::Rc, time::Duration};

use cm_core::application::{AppCommand, Application, RequestId, SubmitError};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::{AppWindow, BuildIdentity, ToastEntry};

mod events;
mod preferences;
mod state;
mod workspace;

use state::{EditorCorrelation, SharedUiState, UiState};

const MAX_ACCEPTED: usize = 64;
const UI_POLL_INTERVAL: Duration = Duration::from_millis(16);

/// Platform-neutral inputs for common workspace and preference UI.
#[derive(Clone)]
pub struct CommonApplicationUiConfig {
    pub application: Rc<dyn Application>,
    pub build_identity: BuildIdentity,
}

impl std::fmt::Debug for CommonApplicationUiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonApplicationUiConfig")
            .field("build_identity", &self.build_identity)
            .finish_non_exhaustive()
    }
}

/// Errors returned before the shared controller is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAttachError {
    BootstrapSubmit(SubmitError),
}

#[derive(Debug, Clone)]
pub(super) enum PendingUiAction {
    Bootstrap,
    RefreshWorkspace,
    Mutation {
        editor: Option<EditorCorrelation>,
    },
    MoveOrderedItem {
        plan_generation: u64,
        step_index: usize,
    },
    SetPreferences {
        generation: u64,
    },
    QueryOutcome {
        original: RequestId,
        action: Box<PendingUiAction>,
    },
}

#[derive(Debug, Clone)]
pub(super) struct CommittedEditor {
    pub request_id: RequestId,
    pub ticket: Option<EditorCorrelation>,
    pub result: cm_core::application::MutationResult,
}

/// Keeps the shared port state, event timer and Toast model alive for a window.
pub struct ApplicationUiController {
    _config: CommonApplicationUiConfig,
    pub(super) state: SharedUiState,
    _ui: slint::Weak<AppWindow>,
    _timer: Timer,
    _toast_model: Rc<VecModel<ToastEntry>>,
}

impl std::fmt::Debug for ApplicationUiController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationUiController")
            .finish_non_exhaustive()
    }
}

/// Attach the shared C1 controller to a generated window and retain the
/// returned value until the window closes.
pub fn attach_application_ui(
    window: &AppWindow,
    config: CommonApplicationUiConfig,
) -> Result<ApplicationUiController, UiAttachError> {
    let toast_model = Rc::new(VecModel::from(Vec::<ToastEntry>::new()));
    let state = Rc::new(RefCell::new(UiState::new(
        config.application.clone(),
        toast_model.clone(),
    )));
    window.set_toasts(ModelRc::from(toast_model.clone()));
    window.set_settings_build_version(config.build_identity.version.clone().into());
    window.set_settings_build_details(config.build_identity.details.clone().into());
    window.set_workspace_loading(true);
    window.set_workspace_load_error(SharedString::default());
    window.set_workspace_refresh_required(false);
    workspace::wire_refresh(window, &state);
    workspace::wire_workspace(window, &state);
    preferences::wire_preferences(window, &state);

    let bootstrap_id = config
        .application
        .submit(AppCommand::Bootstrap)
        .map_err(UiAttachError::BootstrapSubmit)?;
    state
        .borrow_mut()
        .pending
        .insert(bootstrap_id, PendingUiAction::Bootstrap);

    let weak = window.as_weak();
    let event_config = config.clone();
    let event_state = state.clone();
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, UI_POLL_INTERVAL, move || {
        let Some(window) = weak.upgrade() else { return };
        // The controller's normal timer retains this `Application`; the event
        // drain handles at most 64 completions/notifications per UI tick.
        events::drain_events(event_config.application.as_ref(), &event_state, &weak);
        let _ = window;
    });

    Ok(ApplicationUiController {
        _config: config,
        state,
        _ui: window.as_weak(),
        _timer: timer,
        _toast_model: toast_model,
    })
}

pub(super) fn submit(
    ui: &AppWindow,
    state: &SharedUiState,
    command: AppCommand,
    action: PendingUiAction,
) -> Option<RequestId> {
    if state.borrow().pending.len() >= MAX_ACCEPTED {
        push_toast(ui, state, "Too many application requests are pending.");
        return None;
    }
    // `submit` is called through the attached state. The port handle is stored
    // in the state table's caller closure through the AppWindow attachment.
    let application = state.borrow().application.clone();
    match application.submit(command) {
        Ok(request_id) => {
            if let PendingUiAction::MoveOrderedItem {
                plan_generation,
                step_index,
            } = &action
            {
                let mut current = state.borrow_mut();
                if let Some(plan) = current.ordering_plan.as_mut()
                    && plan.generation == *plan_generation
                    && plan.next_index == *step_index
                {
                    plan.next_index = step_index.saturating_add(1);
                }
            }
            if let PendingUiAction::Mutation {
                editor: Some(ticket),
            } = &action
                && let Some(active) = state.borrow_mut().editor_mut(ticket.kind).as_mut()
                && active.instance == ticket.instance
            {
                active.pending = Some(request_id);
                set_editor_pending(ui, ticket.kind, true);
            }
            state.borrow_mut().pending.insert(request_id, action);
            Some(request_id)
        }
        Err(error) => {
            push_toast(ui, state, &format!("Request was not submitted: {error:?}"));
            None
        }
    }
}

pub(super) fn set_editor_pending(ui: &AppWindow, kind: state::EditorKind, pending: bool) {
    match kind {
        state::EditorKind::Profile => ui.set_profile_save_pending(pending),
        state::EditorKind::Group => ui.set_group_save_pending(pending),
        state::EditorKind::Credential => ui.set_cred_save_pending(pending),
        state::EditorKind::CredentialFolder => ui.set_cred_folder_save_pending(pending),
    }
}

pub(super) fn set_editor_error(ui: &AppWindow, kind: state::EditorKind, message: &str) {
    let message = SharedString::from(message);
    match kind {
        state::EditorKind::Profile => ui.set_profile_save_error(message),
        state::EditorKind::Group => ui.set_group_save_error(message),
        state::EditorKind::Credential => ui.set_cred_save_error(message),
        state::EditorKind::CredentialFolder => ui.set_cred_folder_save_error(message),
    }
}

pub(super) fn push_toast(ui: &AppWindow, state: &SharedUiState, message: &str) {
    let (model, id) = {
        let mut state = state.borrow_mut();
        let id = state.toast_next_id;
        state.toast_next_id = state.toast_next_id.saturating_add(1);
        (state.toast_model.clone(), id)
    };
    model.push(ToastEntry {
        id,
        message: message.into(),
        kind: 3,
    });
    ui.set_toasts(ModelRc::from(model));
}

impl ApplicationUiController {
    /// Current revision, useful to diagnostics and focused controller tests.
    pub fn workspace_revision(&self) -> Option<cm_core::application::WorkspaceRevision> {
        self.state.borrow().revision
    }

    pub fn pending_requests(&self) -> usize {
        self.state.borrow().pending.len()
    }
}
