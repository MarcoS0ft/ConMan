use cm_core::application::{
    AppCommand, AppError, BundledFont, GatewayPreferences, MutationMeta, MutationResult,
    WorkspaceMutation,
};
use cm_core::{AccentColor, Density, TerminalTheme, ThemeMode};
use slint::ComponentHandle;

use super::{PendingUiAction, SharedUiState};

pub(super) fn install_preferences(
    ui: &crate::AppWindow,
    value: &GatewayPreferences,
    state: &SharedUiState,
) {
    ui.set_theme_mode(match value.theme {
        ThemeMode::Dark => 0,
        ThemeMode::Light => 1,
        ThemeMode::System => 2,
    });
    ui.set_density(match value.density {
        Density::Compact => 0,
        Density::Cosy => 1,
    });
    ui.set_accent_index(match value.accent_color {
        AccentColor::Blue => 0,
        AccentColor::Teal => 1,
        AccentColor::Green => 2,
        AccentColor::Purple => 3,
        AccentColor::System => 4,
    });
    ui.invoke_apply_accent_index(ui.get_accent_index());
    ui.set_settings_terminal_theme(i32::from(value.terminal_theme == TerminalTheme::Light));
    ui.set_settings_font_size(i32::from(value.font_size));
    ui.set_settings_scrollback_limit(value.scrollback_limit.to_string().into());
    ui.set_settings_always_show_scrollbar(value.always_show_scrollbar);
    ui.set_settings_plain_copy_paste(value.plain_copy_paste_shortcuts);
    ui.set_settings_copy_on_select(value.copy_on_select);
    ui.set_settings_confirm_close_active_tab(value.confirm_close_active_tab);
    state.borrow_mut().preferences = Some(value.clone());
}

fn from_ui(ui: &crate::AppWindow, current: &GatewayPreferences) -> GatewayPreferences {
    GatewayPreferences {
        theme: match ui.get_theme_mode() {
            0 => ThemeMode::Dark,
            1 => ThemeMode::Light,
            _ => ThemeMode::System,
        },
        accent_color: match ui.get_accent_index() {
            1 => AccentColor::Teal,
            2 => AccentColor::Green,
            3 => AccentColor::Purple,
            4 => AccentColor::System,
            _ => AccentColor::Blue,
        },
        density: if ui.get_density() == 1 {
            Density::Cosy
        } else {
            Density::Compact
        },
        terminal_theme: if ui.get_settings_terminal_theme() == 1 {
            TerminalTheme::Light
        } else {
            TerminalTheme::Dark
        },
        bundled_font: BundledFont::JetBrainsMonoNerdFontMono,
        font_size: ui.get_settings_font_size().clamp(8, 72) as u8,
        scrollback_limit: ui
            .get_settings_scrollback_limit()
            .parse()
            .unwrap_or(current.scrollback_limit),
        always_show_scrollbar: ui.get_settings_always_show_scrollbar(),
        plain_copy_paste_shortcuts: ui.get_settings_plain_copy_paste(),
        copy_on_select: ui.get_settings_copy_on_select(),
        confirm_close_active_tab: ui.get_settings_confirm_close_active_tab(),
    }
}

pub(super) fn wire_preferences(ui: &crate::AppWindow, shared: &SharedUiState) {
    macro_rules! changed {
        ($callback:ident) => {{
            let weak = ui.as_weak();
            let state = shared.clone();
            ui.$callback(move |_| {
                if let Some(ui) = weak.upgrade() {
                    queue_preferences(&ui, &state);
                }
            });
        }};
    }
    changed!(on_theme_changed);
    changed!(on_density_changed);
    changed!(on_accent_changed);
    changed!(on_settings_font_size_changed);
    changed!(on_settings_terminal_theme_changed);
    changed!(on_settings_scrollback_limit_changed);
    changed!(on_settings_always_show_scrollbar_changed);
    changed!(on_settings_plain_copy_paste_changed);
    changed!(on_settings_copy_on_select_changed);
    changed!(on_settings_confirm_close_active_tab_changed);
}

fn queue_preferences(ui: &crate::AppWindow, shared: &SharedUiState) {
    let desired = {
        let mut state = shared.borrow_mut();
        let Some(current) = state.preferences.clone() else {
            return;
        };
        state.preference_generation = state.preference_generation.wrapping_add(1).max(1);
        let desired = from_ui(ui, &current);
        state.desired_preferences = Some(desired.clone());
        desired
    };
    ui.set_preferences_save_error("".into());
    submit_latest(ui, shared, desired);
}

fn submit_latest(ui: &crate::AppWindow, shared: &SharedUiState, value: GatewayPreferences) {
    let (generation, revision, in_flight, blocked) = {
        let state = shared.borrow();
        (
            state.preference_generation,
            state.revision,
            state.preferences_in_flight,
            state.refresh_required,
        )
    };
    if in_flight.is_some() || blocked {
        return;
    }
    let Some(revision) = revision else { return };
    let accepted = super::submit(
        ui,
        shared,
        AppCommand::Mutate {
            meta: MutationMeta {
                expected_revision: revision,
            },
            operation: WorkspaceMutation::SetPreferences { value },
        },
        PendingUiAction::SetPreferences { generation },
    );
    if let Some(request_id) = accepted {
        shared.borrow_mut().preferences_in_flight = Some((request_id, generation));
        ui.set_preferences_saving(true);
    }
}

pub(super) fn settled(
    ui: &crate::AppWindow,
    shared: &SharedUiState,
    request_id: cm_core::application::RequestId,
    generation: u64,
    result: Result<MutationResult, AppError>,
    revision: Option<cm_core::application::WorkspaceRevision>,
) {
    let mut authoritative = None;
    let mut next_value = None;
    let mut error_text = None;
    {
        let mut state = shared.borrow_mut();
        if state.preferences_in_flight != Some((request_id, generation)) {
            return;
        }
        state.preferences_in_flight = None;
        if let Some(revision) = revision {
            state.revision = Some(revision);
        }
        match result {
            Ok(MutationResult::Preferences(value)) if generation == state.preference_generation => {
                state.preferences = Some(value.clone());
                state.desired_preferences = None;
                authoritative = Some(value);
            }
            Ok(MutationResult::Preferences(_)) | Ok(_)
                if generation != state.preference_generation =>
            {
                next_value = state.desired_preferences.clone();
            }
            Err(error) if generation != state.preference_generation => {
                next_value = state.desired_preferences.clone();
                error_text = Some(format!("An earlier preference save failed: {error:?}"));
            }
            Err(error)
                if matches!(
                    error,
                    AppError::RevisionConflict { .. }
                        | AppError::PartialRequiresReconcile { .. }
                        | AppError::TransportUncertain { .. }
                ) =>
            {
                // Keep the latest desired value while a reconciliation is in
                // progress. The authoritative workspace event replays it with
                // the newly observed revision.
                next_value = state.desired_preferences.clone();
                error_text = Some(format!("Preference save needs reconciliation: {error:?}"));
            }
            Err(error) => {
                state.desired_preferences = None;
                error_text = Some(format!("Preference save failed: {error:?}"));
            }
            Ok(_) => {
                error_text =
                    Some("The application returned an unexpected preference result.".into())
            }
        }
    }
    ui.set_preferences_saving(false);
    if let Some(value) = authoritative {
        install_preferences(ui, &value, shared);
    }
    if let Some(error) = error_text {
        ui.set_preferences_save_error(error.into());
    }
    if let Some(value) = next_value {
        submit_latest(ui, shared, value);
    }
}

pub(super) fn after_workspace_refresh(ui: &crate::AppWindow, shared: &SharedUiState) {
    let desired = {
        let state = shared.borrow();
        if state.refresh_required || state.preferences_in_flight.is_some() {
            return;
        }
        state.desired_preferences.clone()
    };
    if let Some(value) = desired {
        submit_latest(ui, shared, value);
    }
}
