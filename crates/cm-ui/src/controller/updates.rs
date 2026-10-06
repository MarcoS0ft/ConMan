//! UI-thread bridge for the headless update worker.
//!
//! This module only maps safe [`cm_update::UpdateSnapshot`] values to Slint
//! properties. It never parses release data and never performs network or
//! staging work on the event loop.

use std::cell::RefCell;
use std::rc::Rc;

use cm_core::{AppConfigStore, SettingKey, SettingsService, UpdateChannel};
use cm_update::{UpdateCommand, UpdateEvent, UpdatePreferences, UpdateSnapshot, UpdateState};
use slint::ComponentHandle;

use super::{Ctx, State};
use crate::AppWindow;

pub(super) fn tick(st: &mut State, ui: &AppWindow) {
    let Some(handle) = st.update.as_ref() else {
        return;
    };
    if !st.update_auto_started
        && st.update_started_at.elapsed() >= std::time::Duration::from_secs(1)
    {
        st.update_auto_started = true;
        if let Err(error) = handle.try_submit(UpdateCommand::StartAutomatic) {
            tracing::debug!(%error, "automatic update check was not queued");
        }
    }
    for event in handle.drain(64) {
        match event {
            UpdateEvent::Snapshot(snapshot) => {
                st.update_snapshot = Some(snapshot.clone());
                apply_snapshot(&snapshot, ui);
            }
            UpdateEvent::CompletionHandoffStarted => {
                ui.set_update_status("Handing update to the platform installer".into());
            }
            UpdateEvent::RelaunchRequested => {
                ui.set_update_status("Restarting to complete update".into());
            }
        }
    }
}

pub(super) fn wire_settings(ctx: &Ctx) {
    ctx.ui.on_update_restart({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                super::close::request_update_restart(&state, &ui);
            }
        }
    });

    ctx.ui.on_update_primary({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let snapshot = state.borrow().update_snapshot.clone();
            let Some(snapshot) = snapshot else { return };
            match snapshot.state {
                UpdateState::Ready {
                    action: cm_update::CompletionAction::RestartToApply,
                    ..
                } => super::close::request_update_restart(&state, &ui),
                UpdateState::Ready { action, .. }
                    if action != cm_update::CompletionAction::ManagedExternally =>
                {
                    if let Some(handle) = state.borrow().update.as_ref()
                        && let Err(error) = handle.try_submit(UpdateCommand::BeginCompletion)
                    {
                        tracing::warn!(%error, "could not queue update completion");
                    }
                }
                UpdateState::Available { .. } => {
                    if let Some(handle) = state.borrow().update.as_ref()
                        && let Err(error) = handle.try_submit(UpdateCommand::DownloadAvailable)
                    {
                        tracing::warn!(%error, "could not queue update download");
                    }
                }
                _ => {}
            }
        }
    });

    ctx.ui.on_settings_check_updates({
        let state = ctx.state.clone();
        move || {
            if let Some(handle) = state.borrow().update.as_ref()
                && let Err(error) = handle.try_check_now()
            {
                tracing::warn!(%error, "could not queue manual update check");
            }
        }
    });

    ctx.ui.on_settings_auto_check_updates_changed({
        let state = ctx.state.clone();
        let store = ctx.config_store.clone();
        let weak = ctx.ui.as_weak();
        move |enabled| {
            persist_bool(store.as_ref(), SettingKey::AutoCheckUpdates, enabled);
            submit_preferences(&state, &weak, UpdatePreferenceChange::AutoCheck(enabled));
        }
    });
    ctx.ui.on_settings_auto_download_updates_changed({
        let state = ctx.state.clone();
        let store = ctx.config_store.clone();
        let weak = ctx.ui.as_weak();
        move |enabled| {
            persist_bool(store.as_ref(), SettingKey::AutoDownloadUpdates, enabled);
            submit_preferences(&state, &weak, UpdatePreferenceChange::AutoDownload(enabled));
        }
    });
    ctx.ui.on_settings_update_channel_changed({
        let state = ctx.state.clone();
        let store = ctx.config_store.clone();
        let weak = ctx.ui.as_weak();
        move |index| {
            let channel = if index == 1 {
                UpdateChannel::Dev
            } else {
                UpdateChannel::Stable
            };
            if let Err(error) = SettingsService::new(store.as_ref())
                .set(SettingKey::UpdateChannel, channel.as_str())
            {
                tracing::warn!(%error, "failed to persist update channel");
            }
            submit_preferences(&state, &weak, UpdatePreferenceChange::Channel(channel));
        }
    });
}

fn persist_bool(store: &dyn AppConfigStore, key: SettingKey, enabled: bool) {
    if let Err(error) = SettingsService::new(store).set_bool(key, enabled) {
        tracing::warn!(%error, key = key.as_str(), "failed to persist update preference");
    }
}

enum UpdatePreferenceChange {
    AutoCheck(bool),
    AutoDownload(bool),
    Channel(UpdateChannel),
}

fn submit_preferences(
    state: &Rc<RefCell<State>>,
    weak: &slint::Weak<AppWindow>,
    change: UpdatePreferenceChange,
) {
    let Some(ui) = weak.upgrade() else { return };
    let mut preferences = UpdatePreferences {
        auto_check: ui.get_settings_auto_check_updates(),
        auto_download: ui.get_settings_auto_download_updates(),
        channel: if ui.get_settings_update_channel() == 1 {
            Some(UpdateChannel::Dev)
        } else {
            Some(UpdateChannel::Stable)
        },
    };
    match change {
        UpdatePreferenceChange::AutoCheck(value) => preferences.auto_check = value,
        UpdatePreferenceChange::AutoDownload(value) => preferences.auto_download = value,
        UpdatePreferenceChange::Channel(value) => preferences.channel = Some(value),
    }
    if let Some(handle) = state.borrow().update.as_ref()
        && let Err(error) = handle.try_submit(UpdateCommand::PreferencesChanged(preferences))
    {
        tracing::warn!(%error, "could not queue changed update preferences");
    }
}

pub(super) fn apply_snapshot(snapshot: &UpdateSnapshot, ui: &AppWindow) {
    ui.set_update_enabled(true);
    ui.set_update_can_download(
        matches!(snapshot.state, UpdateState::Available { .. })
            && snapshot.capabilities.can_download,
    );
    ui.set_update_status(snapshot.status.as_str().into());
    ui.set_settings_update_channel(if snapshot.channel == UpdateChannel::Dev {
        1
    } else {
        0
    });
    ui.set_update_available(matches!(
        snapshot.state,
        UpdateState::Available { .. }
            | UpdateState::Downloading { .. }
            | UpdateState::Preparing { .. }
            | UpdateState::Ready { .. }
            | UpdateState::Installing { .. }
    ));
    let (version, progress, ready, action) = match &snapshot.state {
        UpdateState::Available { candidate }
        | UpdateState::Preparing { candidate }
        | UpdateState::Installing { candidate } => (candidate.version.to_string(), 0.0, false, 3),
        UpdateState::Downloading {
            candidate,
            received,
            total,
        } => (
            candidate.version.to_string(),
            if *total == 0 {
                0.0
            } else {
                *received as f32 / *total as f32
            },
            false,
            3,
        ),
        UpdateState::Ready { staged, action } => (
            staged.candidate.version.to_string(),
            1.0,
            true,
            match action {
                cm_update::CompletionAction::RestartToApply => 0,
                cm_update::CompletionAction::FinishInSystemInstaller => 1,
                cm_update::CompletionAction::OpenDownloadedArtifact => 2,
                cm_update::CompletionAction::OpenReleasePage => 3,
                cm_update::CompletionAction::ManagedExternally => 4,
            },
        ),
        _ => (String::new(), 0.0, false, 3),
    };
    ui.set_update_version(version.into());
    ui.set_update_progress(progress);
    ui.set_update_ready(ready);
    ui.set_update_action(action);
}
