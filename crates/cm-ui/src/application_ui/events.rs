use cm_core::application::{
    AppCommand, AppError, AppEvent, AppNotification, AppResult, MutationOutcome, MutationResult,
    RequestId, WorkspaceDto,
};

use super::PendingUiAction;

pub(super) const MAX_EVENTS_PER_TICK: usize = 64;

pub(super) fn drain_events(
    application: &dyn cm_core::application::Application,
    state: &super::SharedUiState,
    weak: &slint::Weak<crate::AppWindow>,
) {
    let Some(ui) = weak.upgrade() else { return };
    for _ in 0..MAX_EVENTS_PER_TICK {
        let Some(event) = application.try_recv() else {
            break;
        };
        match event {
            AppEvent::Completed { request_id, result } => {
                handle_completion(&ui, state, request_id, result);
            }
            AppEvent::Notification(notification) => handle_notification(&ui, state, notification),
        }
    }
}

pub(super) fn handle_completion(
    ui: &crate::AppWindow,
    shared: &super::state::SharedUiState,
    request_id: RequestId,
    result: Result<AppResult, AppError>,
) {
    let action = shared.borrow_mut().pending.remove(&request_id);
    let Some(action) = action else { return };
    // Keep the query wrapper until its result is classified. It carries the
    // original ID needed to settle the request, and a query failure must not
    // be mistaken for another transport failure of the original operation.
    handle_action(ui, shared, request_id, action, result);
}

fn handle_action(
    ui: &crate::AppWindow,
    shared: &super::state::SharedUiState,
    request_id: RequestId,
    action: PendingUiAction,
    result: Result<AppResult, AppError>,
) {
    match (action, result) {
        (PendingUiAction::Bootstrap, Ok(AppResult::Bootstrap(value))) => {
            install_bootstrap(ui, shared, value);
        }
        (PendingUiAction::RefreshWorkspace, Ok(AppResult::Workspace(value))) => {
            install_workspace(ui, shared, value);
        }
        (PendingUiAction::RefreshWorkspace, Err(error)) => {
            ui.set_workspace_loading(false);
            ui.set_workspace_refresh_pending(false);
            ui.set_workspace_refresh_required(true);
            ui.set_workspace_load_error(format!("Workspace refresh failed: {error:?}").into());
            shared.borrow_mut().refresh_required = true;
        }
        (PendingUiAction::Bootstrap, Err(error)) => {
            ui.set_workspace_loading(false);
            ui.set_workspace_load_error(format!("Workspace load failed: {error:?}").into());
            require_refresh(ui, shared);
            super::push_toast(ui, shared, "Workspace could not be loaded. Retry refresh.");
        }
        (
            PendingUiAction::Mutation { editor },
            Ok(AppResult::MutationCommitted { revision, result }),
        ) => {
            commit_mutation(ui, shared, request_id, editor, revision, result);
        }
        (
            PendingUiAction::Mutation { editor },
            Ok(AppResult::MutationOutcome(MutationOutcome::Committed { revision, result })),
        ) => {
            commit_mutation(ui, shared, request_id, editor, revision, result);
        }
        (
            PendingUiAction::MoveOrderedItem {
                plan_generation,
                step_index,
            },
            Ok(AppResult::MutationCommitted { revision, .. }),
        )
        | (
            PendingUiAction::MoveOrderedItem {
                plan_generation,
                step_index,
            },
            Ok(AppResult::MutationOutcome(MutationOutcome::Committed { revision, .. })),
        ) => {
            let next = {
                let mut state = shared.borrow_mut();
                state.revision = Some(revision);
                state
                    .ordering_plan
                    .as_ref()
                    .filter(|p| p.generation == plan_generation && p.next_index == step_index + 1)
                    .map(|_| ())
            };
            if next.is_some() {
                super::workspace::submit_next_order_plan_step(
                    ui,
                    shared,
                    plan_generation,
                    revision,
                );
            } else {
                super::workspace::stop_order_plan(ui, shared);
            }
        }
        (
            PendingUiAction::MoveOrderedItem { .. },
            Ok(AppResult::MutationOutcome(MutationOutcome::Failed {
                current_revision,
                error,
            })),
        ) => {
            shared.borrow_mut().revision = Some(current_revision);
            require_refresh(ui, shared);
            super::workspace::stop_order_plan(ui, shared);
            super::push_toast(
                ui,
                shared,
                &format!("Workspace ordering stopped: {error:?}"),
            );
        }
        (
            PendingUiAction::MoveOrderedItem {
                plan_generation,
                step_index,
            },
            Ok(AppResult::MutationOutcome(MutationOutcome::InProgress)),
        ) => {
            query_outcome(
                ui,
                shared,
                request_id,
                PendingUiAction::MoveOrderedItem {
                    plan_generation,
                    step_index,
                },
            );
        }
        (
            PendingUiAction::MoveOrderedItem {
                plan_generation,
                step_index,
            },
            Err(AppError::TransportUncertain {
                request_id: original,
            }),
        ) => {
            query_outcome(
                ui,
                shared,
                original,
                PendingUiAction::MoveOrderedItem {
                    plan_generation,
                    step_index,
                },
            );
        }
        (PendingUiAction::MoveOrderedItem { .. }, result) => {
            require_refresh(ui, shared);
            super::workspace::stop_order_plan(ui, shared);
            super::push_toast(
                ui,
                shared,
                &format!("Workspace ordering stopped: {result:?}"),
            );
        }
        (
            PendingUiAction::SetPreferences { generation },
            Ok(AppResult::MutationCommitted { revision, result }),
        ) => {
            super::preferences::settled(
                ui,
                shared,
                request_id,
                generation,
                Ok(result),
                Some(revision),
            );
        }
        (
            PendingUiAction::SetPreferences { generation },
            Ok(AppResult::MutationOutcome(MutationOutcome::Committed { revision, result })),
        ) => {
            super::preferences::settled(
                ui,
                shared,
                request_id,
                generation,
                Ok(result),
                Some(revision),
            );
        }
        (
            PendingUiAction::SetPreferences { generation },
            Ok(AppResult::MutationOutcome(MutationOutcome::Failed {
                current_revision,
                error,
            })),
        ) => {
            if matches!(error, AppError::RevisionConflict { .. }) {
                require_refresh(ui, shared);
            }
            super::preferences::settled(
                ui,
                shared,
                request_id,
                generation,
                Err(error),
                Some(current_revision),
            );
        }
        (
            PendingUiAction::SetPreferences { generation },
            Ok(AppResult::MutationOutcome(MutationOutcome::InProgress)),
        ) => {
            query_outcome(
                ui,
                shared,
                request_id,
                PendingUiAction::SetPreferences { generation },
            );
        }
        (
            PendingUiAction::SetPreferences { generation },
            Ok(AppResult::MutationOutcome(MutationOutcome::Unknown { .. })),
        ) => {
            require_refresh(ui, shared);
            super::preferences::settled(
                ui,
                shared,
                request_id,
                generation,
                Err(AppError::TransportUncertain { request_id }),
                None,
            );
        }
        (
            PendingUiAction::SetPreferences { generation },
            Err(AppError::TransportUncertain {
                request_id: original,
            }),
        ) => {
            query_outcome(
                ui,
                shared,
                original,
                PendingUiAction::SetPreferences { generation },
            );
        }
        (PendingUiAction::SetPreferences { generation }, Err(error)) => {
            if matches!(
                error,
                AppError::RevisionConflict { .. } | AppError::PartialRequiresReconcile { .. }
            ) {
                require_refresh(ui, shared);
            }
            super::preferences::settled(ui, shared, request_id, generation, Err(error), None);
        }
        (
            PendingUiAction::Mutation { editor },
            Ok(AppResult::MutationOutcome(MutationOutcome::Failed {
                current_revision,
                error,
            })),
        ) => {
            shared.borrow_mut().revision = Some(current_revision);
            if matches!(error, AppError::RevisionConflict { .. }) {
                require_refresh(ui, shared);
            }
            settle_editor_failure(
                ui,
                shared,
                request_id,
                editor,
                &format!("Workspace change failed: {error:?}"),
            );
        }
        (
            PendingUiAction::Mutation { editor },
            Ok(AppResult::MutationOutcome(MutationOutcome::Unknown { .. })),
        ) => {
            require_refresh(ui, shared);
            settle_editor_failure(
                ui,
                shared,
                request_id,
                editor,
                "The result is uncertain. Refresh the workspace before retrying.",
            );
        }
        (
            PendingUiAction::Mutation { editor },
            Ok(AppResult::MutationOutcome(MutationOutcome::InProgress)),
        ) => {
            query_outcome(ui, shared, request_id, PendingUiAction::Mutation { editor });
        }
        (
            PendingUiAction::Mutation { editor },
            Err(AppError::TransportUncertain {
                request_id: original,
            }),
        ) => {
            query_outcome(ui, shared, original, PendingUiAction::Mutation { editor });
        }
        (PendingUiAction::Mutation { editor }, Err(error)) => {
            if matches!(
                error,
                AppError::RevisionConflict { .. } | AppError::PartialRequiresReconcile { .. }
            ) {
                require_refresh(ui, shared);
            }
            settle_editor_failure(
                ui,
                shared,
                request_id,
                editor,
                &format!("Workspace change failed: {error:?}"),
            );
        }
        (
            PendingUiAction::QueryOutcome { original, action },
            Ok(AppResult::MutationOutcome(MutationOutcome::InProgress)),
        ) => {
            query_outcome(ui, shared, original, *action);
        }
        (
            PendingUiAction::QueryOutcome { original, action },
            Ok(AppResult::MutationOutcome(MutationOutcome::Unknown {
                current_revision, ..
            })),
        ) => {
            shared.borrow_mut().revision = Some(current_revision);
            settle_uncertain_action(
                ui,
                shared,
                original,
                *action,
                "The mutation result is unknown. Refresh before retrying.",
            );
        }
        (PendingUiAction::QueryOutcome { original, action }, result) => match result {
            Ok(AppResult::MutationCommitted { .. })
            | Ok(AppResult::MutationOutcome(MutationOutcome::Committed { .. }))
            | Ok(AppResult::MutationOutcome(MutationOutcome::Failed { .. })) => {
                handle_action(ui, shared, original, *action, result);
            }
            _ => settle_uncertain_action(
                ui,
                shared,
                original,
                *action,
                "The mutation outcome could not be confirmed. Refresh before retrying.",
            ),
        },
        (_, Ok(_)) => {
            super::push_toast(ui, shared, "The application returned an unexpected result.")
        }
    }
}

fn commit_mutation(
    ui: &crate::AppWindow,
    shared: &super::state::SharedUiState,
    request_id: RequestId,
    editor: Option<super::state::EditorCorrelation>,
    revision: cm_core::application::WorkspaceRevision,
    _result: MutationResult,
) {
    shared.borrow_mut().revision = Some(revision);
    settle_editor_success(ui, shared, request_id, editor);
    // A mutation result supplies identity, not the full authoritative DTO.
    // Gate subsequent mutations until the accepted refresh reconciles it.
    require_refresh(ui, shared);
    submit_refresh(ui, shared);
}

/// Reconcile an accepted request before allowing another write. If the
/// service cannot accept the outcome query, keep the uncertainty visible and
/// release transient editor state so refresh remains available.
fn query_outcome(
    ui: &crate::AppWindow,
    shared: &super::SharedUiState,
    original: RequestId,
    action: PendingUiAction,
) {
    let query = super::submit(
        ui,
        shared,
        AppCommand::QueryOutcome {
            original_request_id: original,
        },
        PendingUiAction::QueryOutcome {
            original,
            action: Box::new(action.clone()),
        },
    );
    if query.is_some() {
        return;
    }
    settle_uncertain_action(
        ui,
        shared,
        original,
        action,
        "The result is uncertain and could not be queried. Refresh before retrying.",
    );
}

fn settle_uncertain_action(
    ui: &crate::AppWindow,
    shared: &super::SharedUiState,
    original: RequestId,
    action: PendingUiAction,
    message: &str,
) {
    require_refresh(ui, shared);
    match action {
        PendingUiAction::Mutation { editor } => {
            settle_editor_failure(ui, shared, original, editor, message)
        }
        PendingUiAction::MoveOrderedItem { .. } => {
            super::workspace::stop_order_plan(ui, shared);
        }
        PendingUiAction::SetPreferences { generation } => super::preferences::settled(
            ui,
            shared,
            original,
            generation,
            Err(AppError::TransportUncertain {
                request_id: original,
            }),
            None,
        ),
        PendingUiAction::Bootstrap | PendingUiAction::RefreshWorkspace => {
            super::push_toast(ui, shared, message);
        }
        PendingUiAction::QueryOutcome { .. } => unreachable!("nested outcome query"),
    }
}

fn settle_editor_success(
    ui: &crate::AppWindow,
    shared: &super::state::SharedUiState,
    request_id: RequestId,
    ticket: Option<super::state::EditorCorrelation>,
) {
    let Some(ticket) = ticket else { return };
    let mut state = shared.borrow_mut();
    let Some(active) = state.editor_mut(ticket.kind).as_mut() else {
        return;
    };
    if active.instance != ticket.instance || active.pending != Some(request_id) {
        return;
    }
    active.pending = None;
    super::set_editor_pending(ui, ticket.kind, false);
    if active.edit_generation == ticket.edit_generation {
        *state.editor_mut(ticket.kind) = None;
        close_editor(ui, ticket.kind);
    }
}

fn settle_editor_failure(
    ui: &crate::AppWindow,
    shared: &super::state::SharedUiState,
    request_id: RequestId,
    ticket: Option<super::state::EditorCorrelation>,
    message: &str,
) {
    let Some(ticket) = ticket else {
        super::push_toast(ui, shared, message);
        return;
    };
    let current_generation = {
        let mut state = shared.borrow_mut();
        match state.editor_mut(ticket.kind).as_mut() {
            Some(active)
                if active.instance == ticket.instance && active.pending == Some(request_id) =>
            {
                active.pending = None;
                Some(active.edit_generation)
            }
            _ => None,
        }
    };
    let Some(current_generation) = current_generation else {
        super::push_toast(ui, shared, message);
        return;
    };
    super::set_editor_pending(ui, ticket.kind, false);
    if current_generation == ticket.edit_generation {
        super::set_editor_error(ui, ticket.kind, message);
    } else {
        super::push_toast(ui, shared, message);
    }
}

fn close_editor(ui: &crate::AppWindow, kind: super::state::EditorKind) {
    match kind {
        super::state::EditorKind::Profile => {
            let mut form = ui.get_profile_form();
            form.inline_password = "".into();
            ui.set_profile_form(form);
            ui.set_profile_editor_open(false);
        }
        super::state::EditorKind::Group => ui.set_group_editor_open(false),
        super::state::EditorKind::Credential => {
            let mut form = ui.get_cred_form();
            form.secret = "".into();
            form.passphrase = "".into();
            ui.set_cred_form(form);
            ui.set_cred_editor_open(false);
        }
        super::state::EditorKind::CredentialFolder => ui.set_cred_folder_editor_open(false),
    }
}

fn install_bootstrap(
    ui: &crate::AppWindow,
    shared: &super::state::SharedUiState,
    value: cm_core::application::BootstrapDto,
) {
    let workspace = value.workspace.clone();
    let preferences = value.preferences.clone();
    {
        let mut state = shared.borrow_mut();
        state.revision = Some(workspace.revision);
        state.workspace = Some(workspace.clone());
        state.preferences = Some(value.preferences.clone());
        state.bootstrap = Some(value);
        state.refresh_required = false;
    }
    super::workspace::install_workspace_models(ui, &workspace);
    super::preferences::install_preferences(ui, &preferences, shared);
    ui.set_workspace_loading(false);
    ui.set_workspace_load_error("".into());
    ui.set_workspace_refresh_required(false);
    ui.set_workspace_refresh_pending(false);
    super::preferences::after_workspace_refresh(ui, shared);
}

fn install_workspace(
    ui: &crate::AppWindow,
    shared: &super::state::SharedUiState,
    value: WorkspaceDto,
) {
    {
        let mut state = shared.borrow_mut();
        state.revision = Some(value.revision);
        state.workspace = Some(value.clone());
        state.refresh_required = false;
    }
    super::workspace::install_workspace_models(ui, &value);
    ui.set_workspace_loading(false);
    ui.set_workspace_refresh_required(false);
    ui.set_workspace_refresh_pending(false);
    ui.set_workspace_load_error("".into());
    super::preferences::after_workspace_refresh(ui, shared);
}

pub(super) fn require_refresh(ui: &crate::AppWindow, shared: &super::state::SharedUiState) {
    shared.borrow_mut().refresh_required = true;
    ui.set_workspace_refresh_required(true);
}

pub(super) fn submit_refresh(ui: &crate::AppWindow, shared: &super::state::SharedUiState) {
    ui.set_workspace_refresh_pending(true);
    if super::submit(
        ui,
        shared,
        AppCommand::ListWorkspace,
        PendingUiAction::RefreshWorkspace,
    )
    .is_none()
    {
        ui.set_workspace_refresh_pending(false);
        require_refresh(ui, shared);
    }
}

fn handle_notification(
    ui: &crate::AppWindow,
    shared: &super::SharedUiState,
    notification: AppNotification,
) {
    if let AppNotification::ApplicationFailure { reason } = notification {
        super::push_toast(
            ui,
            shared,
            &format!("Application service failed: {reason:?}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use cm_core::application::{
        AppCommand, AppError, AppEvent, AppResult, Application, ApplicationMailbox,
        GatewayPreferences, MutationMeta, MutationOutcome, MutationResult, RequestId, ResultClass,
        SubmitError, WorkspaceDto, WorkspaceMutation, WorkspaceRevision,
    };
    use cm_core::{AccentColor, Density, TerminalTheme, ThemeMode};
    use slint::ComponentHandle;
    use slint::VecModel;

    use super::*;
    use crate::{
        ToastEntry,
        application_ui::{
            PendingUiAction,
            state::{EditorKind, UiState},
        },
    };

    thread_local! {
        static BACKEND_READY: Cell<bool> = const { Cell::new(false) };
    }

    #[derive(Default)]
    struct TestApplication {
        mailbox: RefCell<ApplicationMailbox>,
        reject_next: Cell<bool>,
    }

    impl Application for TestApplication {
        fn submit(&self, command: AppCommand) -> Result<RequestId, SubmitError> {
            if self.reject_next.replace(false) {
                return Err(SubmitError::QueueFull);
            }
            let mut mailbox = self.mailbox.borrow_mut();
            let result_class = if matches!(
                &command,
                AppCommand::Bootstrap | AppCommand::ListWorkspace | AppCommand::QueryOutcome { .. }
            ) {
                ResultClass::Workspace
            } else {
                ResultClass::Standard
            };
            let id = mailbox.accept(command)?;
            mailbox.reserve_result(id, result_class)?;
            Ok(id)
        }

        fn try_recv(&self) -> Option<AppEvent> {
            self.mailbox.borrow_mut().try_recv()
        }
    }

    fn setup() -> (
        crate::AppWindow,
        Rc<TestApplication>,
        super::super::SharedUiState,
    ) {
        BACKEND_READY.with(|ready| {
            if !ready.get() {
                i_slint_backend_testing::init_no_event_loop();
                ready.set(true);
            }
        });
        let ui = crate::AppWindow::new().expect("AppWindow::new");
        let app = Rc::new(TestApplication::default());
        let toast = Rc::new(VecModel::from(Vec::<ToastEntry>::new()));
        let shared = Rc::new(RefCell::new(UiState::new(app.clone(), toast)));
        shared.borrow_mut().revision = Some(WorkspaceRevision(1));
        (ui, app, shared)
    }

    fn prefs() -> GatewayPreferences {
        GatewayPreferences {
            theme: ThemeMode::Dark,
            accent_color: AccentColor::Blue,
            density: Density::Compact,
            terminal_theme: TerminalTheme::Dark,
            bundled_font: cm_core::application::BundledFont::JetBrainsMonoNerdFontMono,
            font_size: 14,
            scrollback_limit: 10_000,
            always_show_scrollbar: false,
            plain_copy_paste_shortcuts: false,
            copy_on_select: false,
            confirm_close_active_tab: true,
        }
    }

    fn submit_action(
        app: &TestApplication,
        state: &super::super::SharedUiState,
        action: PendingUiAction,
    ) -> RequestId {
        let command = match &action {
            PendingUiAction::Bootstrap => AppCommand::Bootstrap,
            PendingUiAction::RefreshWorkspace => AppCommand::ListWorkspace,
            PendingUiAction::QueryOutcome { original, .. } => AppCommand::QueryOutcome {
                original_request_id: *original,
            },
            PendingUiAction::SetPreferences { .. } => AppCommand::Mutate {
                meta: MutationMeta {
                    expected_revision: state.borrow().revision.unwrap_or(WorkspaceRevision(0)),
                },
                operation: WorkspaceMutation::SetPreferences { value: prefs() },
            },
            PendingUiAction::MoveOrderedItem {
                plan_generation,
                step_index,
            } => {
                let change = state
                    .borrow()
                    .ordering_plan
                    .as_ref()
                    .filter(|plan| plan.generation == *plan_generation)
                    .and_then(|plan| plan.changes.get(*step_index).copied())
                    .expect("order plan step exists");
                AppCommand::Mutate {
                    meta: MutationMeta {
                        expected_revision: state.borrow().revision.unwrap_or(WorkspaceRevision(0)),
                    },
                    operation: change.into_mutation(),
                }
            }
            PendingUiAction::Mutation { .. } => AppCommand::Mutate {
                meta: MutationMeta {
                    expected_revision: state.borrow().revision.unwrap_or(WorkspaceRevision(0)),
                },
                operation: WorkspaceMutation::MoveGroup {
                    id: cm_core::GroupId::new(1),
                    parent_id: None,
                    sort: 0,
                },
            },
        };
        let id = app.submit(command).unwrap();
        let _ = app.mailbox.borrow_mut().take_command();
        if let PendingUiAction::Mutation {
            editor: Some(ticket),
        } = &action
            && let Some(editor) = state.borrow_mut().editor_mut(ticket.kind).as_mut()
            && editor.instance == ticket.instance
        {
            editor.pending = Some(id);
        }
        state.borrow_mut().pending.insert(id, action);
        id
    }

    fn deliver(
        app: &TestApplication,
        ui: &crate::AppWindow,
        state: &super::super::SharedUiState,
        request: RequestId,
        result: Result<AppResult, AppError>,
    ) {
        app.mailbox
            .borrow_mut()
            .enqueue_completion(request, result)
            .unwrap();
        drain_events(app, state, &ui.as_weak());
    }

    #[test]
    fn failed_editor_save_preserves_newer_draft_and_stale_reopen_isolated() {
        let (ui, app, shared) = setup();
        for kind in [
            EditorKind::Profile,
            EditorKind::Group,
            EditorKind::Credential,
            EditorKind::CredentialFolder,
        ] {
            let ticket = shared.borrow_mut().open_editor(kind);
            let request = submit_action(
                &app,
                &shared,
                PendingUiAction::Mutation {
                    editor: Some(ticket),
                },
            );
            shared
                .borrow_mut()
                .editor_mut(kind)
                .as_mut()
                .unwrap()
                .edit_generation += 1;
            deliver(
                &app,
                &ui,
                &shared,
                request,
                Err(AppError::PersistenceFailed),
            );
            let active = shared.borrow().editor(kind).unwrap();
            assert_eq!(active.instance, ticket.instance);
            assert_eq!(active.edit_generation, ticket.edit_generation + 1);
            assert_eq!(active.pending, None);
        }

        let stale = shared.borrow_mut().open_editor(EditorKind::Profile);
        let request = submit_action(
            &app,
            &shared,
            PendingUiAction::Mutation {
                editor: Some(stale),
            },
        );
        shared.borrow_mut().profile_editor = None;
        let reopened = shared.borrow_mut().open_editor(EditorKind::Profile);
        deliver(
            &app,
            &ui,
            &shared,
            request,
            Ok(AppResult::MutationOutcome(MutationOutcome::Committed {
                revision: WorkspaceRevision(2),
                result: MutationResult::Deleted,
            })),
        );
        assert_eq!(
            shared.borrow().profile_editor.unwrap().instance,
            reopened.instance
        );
        assert!(shared.borrow().refresh_required);
    }

    #[test]
    fn failed_workspace_refresh_preserves_draft_and_allows_retry() {
        let (ui, app, shared) = setup();
        let ticket = shared.borrow_mut().open_editor(EditorKind::Profile);
        let request = submit_action(&app, &shared, PendingUiAction::RefreshWorkspace);
        deliver(
            &app,
            &ui,
            &shared,
            request,
            Err(AppError::PersistenceFailed),
        );
        assert_eq!(
            shared.borrow().profile_editor.unwrap().instance,
            ticket.instance
        );
        assert!(shared.borrow().refresh_required);
        submit_refresh(&ui, &shared);
        assert!(ui.get_workspace_refresh_pending());
    }

    #[test]
    fn preference_conflict_replays_latest_value_only_after_workspace_refresh() {
        let (ui, app, shared) = setup();
        let request = submit_action(
            &app,
            &shared,
            PendingUiAction::SetPreferences { generation: 4 },
        );
        {
            let mut state = shared.borrow_mut();
            state.preferences = Some(prefs());
            state.desired_preferences = Some(prefs());
            state.preference_generation = 4;
            state.preferences_in_flight = Some((request, 4));
        }
        deliver(
            &app,
            &ui,
            &shared,
            request,
            Ok(AppResult::MutationOutcome(MutationOutcome::Failed {
                current_revision: WorkspaceRevision(7),
                error: AppError::RevisionConflict {
                    current_revision: WorkspaceRevision(7),
                },
            })),
        );
        assert!(shared.borrow().refresh_required);
        assert!(shared.borrow().desired_preferences.is_some());
        assert_eq!(shared.borrow().preferences_in_flight, None);

        let refresh = submit_action(&app, &shared, PendingUiAction::RefreshWorkspace);
        deliver(
            &app,
            &ui,
            &shared,
            refresh,
            Ok(AppResult::Workspace(WorkspaceDto {
                revision: WorkspaceRevision(7),
                connections: vec![],
                groups: vec![],
                credentials: vec![],
                credential_folders: vec![],
            })),
        );
        assert!(!shared.borrow().refresh_required);
        assert!(shared.borrow().preferences_in_flight.is_some());
    }

    #[test]
    fn failed_outcome_query_releases_editor_and_keeps_refresh_gate() {
        let (ui, app, shared) = setup();
        let ticket = shared.borrow_mut().open_editor(EditorKind::Credential);
        let request = submit_action(
            &app,
            &shared,
            PendingUiAction::Mutation {
                editor: Some(ticket),
            },
        );
        app.reject_next.set(true);
        query_outcome(
            &ui,
            &shared,
            request,
            PendingUiAction::Mutation {
                editor: Some(ticket),
            },
        );
        assert_eq!(shared.borrow().credential_editor.unwrap().pending, None);
        assert!(shared.borrow().refresh_required);
        assert!(ui.get_workspace_refresh_required());

        // An accepted query that itself fails must terminate uncertainty
        // rather than recursively issuing outcome queries forever.
        shared.borrow_mut().refresh_required = false;
        ui.set_workspace_refresh_required(false);
        let next_ticket = shared.borrow_mut().open_editor(EditorKind::Profile);
        let original = submit_action(
            &app,
            &shared,
            PendingUiAction::Mutation {
                editor: Some(next_ticket),
            },
        );
        deliver(
            &app,
            &ui,
            &shared,
            original,
            Err(AppError::TransportUncertain {
                request_id: original,
            }),
        );
        let query = shared
            .borrow()
            .pending
            .iter()
            .find_map(|(id, action)| matches!(action, PendingUiAction::QueryOutcome { original: id0, .. } if *id0 == original).then_some(*id))
            .expect("accepted query is tracked");
        deliver(&app, &ui, &shared, query, Err(AppError::PersistenceFailed));
        assert_eq!(shared.borrow().profile_editor.unwrap().pending, None);
        assert!(shared.borrow().refresh_required);
    }

    #[test]
    fn folder_order_partial_failure_never_replays_remaining_moves() {
        let (ui, app, shared) = setup();
        shared.borrow_mut().ordering_plan = Some(super::super::state::WorkspaceReorderPlan {
            generation: 44,
            kind: super::super::state::OrderKind::CredentialFolders,
            changes: vec![
                super::super::state::OrderedMove::CredentialFolder {
                    id: cm_core::CredentialFolderId::new(2),
                    parent_id: None,
                    sort: 0,
                },
                super::super::state::OrderedMove::CredentialFolder {
                    id: cm_core::CredentialFolderId::new(3),
                    parent_id: None,
                    sort: 1,
                },
            ],
            next_index: 1,
        });
        let request = submit_action(
            &app,
            &shared,
            PendingUiAction::MoveOrderedItem {
                plan_generation: 44,
                step_index: 0,
            },
        );
        deliver(
            &app,
            &ui,
            &shared,
            request,
            Ok(AppResult::MutationOutcome(MutationOutcome::Failed {
                current_revision: WorkspaceRevision(9),
                error: AppError::PersistenceFailed,
            })),
        );
        assert_eq!(shared.borrow().revision, Some(WorkspaceRevision(9)));
        assert!(shared.borrow().ordering_plan.is_none());
        let commands: Vec<_> = std::iter::from_fn(|| app.mailbox.borrow_mut().take_command())
            .map(|(_, command)| command)
            .collect();
        assert!(
            commands
                .iter()
                .all(|command| matches!(command, AppCommand::ListWorkspace))
        );
    }
}
