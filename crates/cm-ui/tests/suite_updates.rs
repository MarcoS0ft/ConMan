//! Exercise the real UI callbacks against the shared update worker.
#![cfg(all(feature = "ui-introspection", not(target_arch = "wasm32")))]

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cm_core::UpdateChannel;
use cm_update::{
    Architecture, AssetKind, BackendCapabilities, BackendCommand, BackendEvent, CompletionAction,
    CurrentBuild, InstallContext, ManifestAsset, Platform, StagedUpdate, UpdateBackend,
    UpdateCandidate, UpdateCommand, UpdateController, UpdateError, UpdatePreferences, UpdateWorker,
};
use support::{harness, harness_with_update, pump_ticks};

struct RecordingBackend {
    completion: CompletionAction,
    commands: Arc<Mutex<Vec<BackendCommand>>>,
    events: Arc<Mutex<Vec<BackendEvent>>>,
}

impl UpdateBackend for RecordingBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            can_download: true,
            can_install: true,
            completion: self.completion,
        }
    }

    fn submit(&mut self, command: BackendCommand) -> Result<(), UpdateError> {
        self.commands.lock().unwrap().push(command);
        Ok(())
    }

    fn drain_events(&mut self) -> Vec<BackendEvent> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }

    fn shutdown(&mut self, _deadline: Instant) {}
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        pump_ticks(1);
        if predicate() {
            return;
        }
        assert!(Instant::now() < deadline, "update worker timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn update_actions_use_the_platform_handoff_without_closing_sessions() {
    i_slint_backend_testing::init_integration_test_with_mock_time();
    let (h, _, _) = harness();
    assert!(!h.ui.get_update_enabled());
    assert!(h.ui.get_update_status().contains("unavailable"));
    drop(h);

    for completion in [
        CompletionAction::FinishInSystemInstaller,
        CompletionAction::OpenDownloadedArtifact,
        CompletionAction::OpenReleasePage,
        CompletionAction::ManagedExternally,
    ] {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let backend = RecordingBackend {
            completion,
            commands: commands.clone(),
            events: events.clone(),
        };
        let candidate = UpdateCandidate {
            version: "0.2.0".parse().unwrap(),
            revision: 2,
            commit: [1; 20],
            channel: UpdateChannel::Stable,
            release_tag: "v0.2.0".into(),
            minimum_updater_version: "0.1.0".parse().unwrap(),
            asset: ManifestAsset {
                platform: Platform::Linux,
                architecture: Architecture::X86_64,
                kind: AssetKind::LinuxDeb,
                asset_name: "conman.deb".into(),
                byte_length: 1,
                sha256: cm_update::sha256_hex(&[0]),
            },
            release_url: "https://github.com/MarcoS0ft/ConMan/releases/tag/v0.2.0".into(),
        };
        let mut controller = UpdateController::new(
            backend,
            CurrentBuild {
                version: "0.1.0".parse().unwrap(),
                commit: Some([1; 20]),
                revision: Some(1),
                dirty: false,
                platform: Platform::Linux,
                architecture: Architecture::X86_64,
                install: InstallContext::Package,
            },
            "0.1.0".parse().unwrap(),
            UpdatePreferences {
                auto_check: false,
                auto_download: false,
                channel: Some(UpdateChannel::Stable),
            },
        );
        controller.dispatch(UpdateCommand::CheckNow).unwrap();
        events.lock().unwrap().push(BackendEvent::Candidate {
            generation: controller.generation(),
            candidate: candidate.clone(),
        });
        controller.poll_backend();
        controller
            .dispatch(UpdateCommand::DownloadAvailable)
            .unwrap();
        events.lock().unwrap().push(BackendEvent::Ready {
            generation: controller.generation(),
            staged: StagedUpdate {
                byte_length: candidate.asset.byte_length,
                sha256: candidate.asset.sha256.clone(),
                candidate,
                platform_token: "test-staging".into(),
            },
        });
        controller.poll_backend();
        commands.lock().unwrap().clear();
        let (handle, worker) = UpdateWorker::spawn(controller);
        let (h, _, _) = harness_with_update(handle);
        wait_for(|| h.ui.get_update_ready());
        assert!(h.ui.get_update_enabled());
        h.ui.invoke_update_primary();
        if completion == CompletionAction::ManagedExternally {
            assert!(commands.lock().unwrap().is_empty());
        } else {
            wait_for(|| !commands.lock().unwrap().is_empty());
            assert!(matches!(
                commands.lock().unwrap().as_slice(),
                [BackendCommand::BeginCompletion { .. }]
            ));
        }
        assert!(!h.ui.get_close_confirm_open());
        drop(h);
        drop(worker);
    }
}
