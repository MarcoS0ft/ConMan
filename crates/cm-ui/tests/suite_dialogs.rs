//! Dialog tests cover quick-connect and profile-editor field manifests per
//! kind, kind-switch port defaults, Save/Cancel persistence, and dialog/button
//! geometry. They cover the "New connection" / "Edit connection" / "Quick
//! connect" journeys, including RDP port and Domain/Resolution fields.
//!
//! Every scenario below actively DRIVES the dialog open and switches its kind
//! before asserting field presence -- `visit_descendants`/`find_by_*` only
//! ever walk the *resting* tree, and per-kind fields are behind real `if`
//! conditions in `.slint` (conditionally instantiated, not just hidden), so a
//! field that isn't the current kind's genuinely does not exist in the tree
//! yet. Checking presence/absence without first switching to that kind would
//! silently pass on the wrong state and prove nothing.
//!
//! One process, one `#[test]`, scenarios run sequentially (each builds its
//! own fresh [`support::harness`] -- a fresh in-memory repo + a fresh
//! `AppWindow` -- so scenarios never see each other's state).

#![cfg(feature = "ui-introspection")]

mod support;

use i_slint_backend_testing::{ElementHandle, ElementRoot};
use slint::ComponentHandle;

slint::slint! {
    import { Theme } from "../ui/theme.slint";

    export component ThemeProbe inherits Window {
        in-out property <bool> dark-mode <=> Theme.dark-mode;
        out property <color> overlay: Theme.color-overlay;
        out property <color> card: Theme.color-card;
        out property <color> elevated: Theme.color-elevated;
        out property <color> base: Theme.color-base;
        out property <color> connecting-foreground: Theme.color-connecting-foreground;
        out property <color> error-foreground: Theme.color-error-foreground;
    }
}

use support::{
    find_by_id, find_by_id_opt, find_descendant_by_label, find_descendant_by_label_opt,
    find_singleton, harness, nth_by_id, pump_ticks,
};

#[test]
fn dialogs_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    quick_connect_ssh_default_manifest();
    quick_connect_rdp_manifest_and_kind_switch();
    quick_connect_telnet_manifest_warning_and_port_rules();
    quick_connect_local_manifest();
    quick_connect_host_and_port_never_overlap();
    profile_editor_new_ssh_default_manifest();
    profile_editor_kind_switch_updates_port_and_manifest();
    profile_editor_telnet_clears_credentials_and_saves_prompt();
    profile_editor_new_connection_username_is_editable_with_no_credential();
    profile_editor_inline_mode_shows_password_hides_credential_picker();
    profile_editor_credential_mode_selector_has_no_prompt_option();
    profile_editor_reference_mode_with_named_credential_is_read_only();
    profile_editor_save_persists_and_cancel_discards();
    profile_editor_cancel_clears_the_transient_inline_password();
    profile_editor_fields_stay_packed_and_scroll_clear_of_footer();
    semantic_foregrounds_meet_normal_text_contrast();
    dialog_and_button_bounds();
    cred_row_activate_and_a11y_survive_the_content_cell_restructure();
}

// ── Quick-connect (screens/dialogs.slint::QuickConnectForm) ────────────────

/// SSH is the dialog's default kind (`qc-kind: 0`): Host, Port=22, Username
/// present; RDP-only (Domain/Resolution) and Local-only (Program/Args/Cwd)
/// fields absent.
fn quick_connect_ssh_default_manifest() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_quick_connect();
    pump_ticks(1);
    assert!(h.ui.get_quick_connect_open(), "quick-connect did not open");
    assert_eq!(
        h.ui.get_qc_kind(),
        0,
        "quick-connect defaults to SSH (kind 0)"
    );

    find_by_id(&h.ui, "QuickConnectForm::qc-host-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-username-field");
    assert_eq!(h.ui.get_qc_port().as_str(), "22", "SSH default port");

    for absent in [
        "QuickConnectForm::qc-rdp-domain-field",
        "QuickConnectForm::qc-rdp-resolution-field",
        "QuickConnectForm::qc-rdp-password-field",
        "QuickConnectForm::qc-local-program-field",
        "QuickConnectForm::qc-local-args-field",
        "QuickConnectForm::qc-local-cwd-field",
    ] {
        assert!(
            find_by_id_opt(&h.ui, absent).is_none(),
            "{absent} must not exist for SSH kind"
        );
    }
}

/// Switching the kind selector to RDP (via the real `SegmentedControl`
/// element, not a raw property poke) must both update the port default
/// (22 -> 3389, the `changed kind` handler in `screens/dialogs.slint`) and
/// swap in the RDP-only fields (Domain, Resolution, password) while removing
/// the SSH-only auth-method fields.
fn quick_connect_rdp_manifest_and_kind_switch() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_quick_connect();
    pump_ticks(1);

    let qc = find_singleton(&h.ui, "QuickConnectForm");
    let rdp_tab = find_descendant_by_label(&qc, "RDP");
    rdp_tab.invoke_accessible_default_action();
    // The `changed kind => {...}` port-default side effect (and the newly
    // (in)stantiated per-kind `if` fields) are only flushed by the property
    // change-tracker / repeater-instantiation pass `mock_elapsed_time` runs
    // (see `i_slint_backend_testing::testing_backend::mock_elapsed_time`) --
    // a bare property/callback write alone does not settle them.
    pump_ticks(1);

    assert_eq!(h.ui.get_qc_kind(), 1, "kind switch to RDP did not take");
    assert_eq!(
        h.ui.get_qc_port().as_str(),
        "3389",
        "kind switch to RDP must update the untouched port default (22 -> 3389)"
    );

    find_by_id(&h.ui, "QuickConnectForm::qc-host-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-username-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-rdp-domain-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-rdp-resolution-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-rdp-password-field");

    for absent in [
        "QuickConnectForm::qc-secret-field",
        "QuickConnectForm::qc-passphrase-field",
        "QuickConnectForm::qc-password-field",
        "QuickConnectForm::qc-local-program-field",
    ] {
        assert!(
            find_by_id_opt(&h.ui, absent).is_none(),
            "{absent} (SSH/Local-only) must not exist for RDP kind"
        );
    }
}

fn quick_connect_telnet_manifest_warning_and_port_rules() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_quick_connect();
    pump_ticks(1);

    let qc = find_singleton(&h.ui, "QuickConnectForm");
    find_descendant_by_label(&qc, "Telnet").invoke_accessible_default_action();
    pump_ticks(1);

    assert_eq!(h.ui.get_qc_kind(), 2);
    assert_eq!(h.ui.get_qc_port().as_str(), "23");
    find_by_id(&h.ui, "QuickConnectForm::qc-host-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-port-field");
    let warning = find_by_id(&h.ui, "QuickConnectForm::qc-telnet-warning");
    assert_eq!(
        warning.accessible_label().as_deref(),
        Some("Telnet is unencrypted. Credentials and session data are sent in clear text.")
    );
    for absent in [
        "QuickConnectForm::qc-username-field",
        "QuickConnectForm::qc-secret-field",
        "QuickConnectForm::qc-passphrase-field",
        "QuickConnectForm::qc-password-field",
        "QuickConnectForm::qc-rdp-domain-field",
        "QuickConnectForm::qc-rdp-resolution-field",
        "QuickConnectForm::qc-rdp-password-field",
        "QuickConnectForm::qc-local-program-field",
    ] {
        assert!(
            find_by_id_opt(&h.ui, absent).is_none(),
            "{absent} must not exist for Telnet"
        );
    }

    // A non-default typed port survives protocol switches.
    h.ui.set_qc_port("2323".into());
    find_descendant_by_label(&qc, "SSH").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_qc_port().as_str(), "2323");
    find_descendant_by_label(&qc, "Telnet").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_qc_port().as_str(), "2323");
}

/// Local has no host/port/username/auth at all -- just the program/args/cwd
/// trio.
fn quick_connect_local_manifest() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_quick_connect();
    pump_ticks(1);

    let qc = find_singleton(&h.ui, "QuickConnectForm");
    let local_tab = find_descendant_by_label(&qc, "Local");
    local_tab.invoke_accessible_default_action();
    pump_ticks(1);

    assert_eq!(h.ui.get_qc_kind(), 3);
    find_by_id(&h.ui, "QuickConnectForm::qc-local-program-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-local-args-field");
    find_by_id(&h.ui, "QuickConnectForm::qc-local-cwd-field");

    for absent in [
        "QuickConnectForm::qc-host-field",
        "QuickConnectForm::qc-port-field",
        "QuickConnectForm::qc-username-field",
    ] {
        assert!(
            find_by_id_opt(&h.ui, absent).is_none(),
            "{absent} must not exist for Local kind"
        );
    }
}

/// Exercise the real per-protocol form instances and nested inputs in
/// both responsive branches. The narrow case is deliberately below the old
/// fixed 520px dialog plus margins, so merely shrinking the outer window while
/// leaving the form untouched cannot satisfy these assertions.
fn quick_connect_host_and_port_never_overlap() {
    for (window_width, narrow) in [(1600.0, false), (480.0, true)] {
        for (kind, label) in [(0, "SSH"), (1, "RDP"), (2, "Telnet")] {
            let (h, _repo, _provider) = harness();
            h.ui.window()
                .set_size(slint::LogicalSize::new(window_width, 900.0));
            pump_ticks(1);
            h.ui.invoke_quick_connect();
            pump_ticks(1);

            let qc = find_singleton(&h.ui, "QuickConnectForm");
            find_descendant_by_label(&qc, label).invoke_accessible_default_action();
            pump_ticks(1);
            assert_eq!(h.ui.get_qc_kind(), kind);
            assert_within(&qc, &h.ui.root_element(), "QuickConnectForm", "window");
            assert!(
                qc.size().width <= window_width - 48.0 + 0.5,
                "{label} form must preserve 24px side margins at {window_width}px, got {:?}",
                qc.size()
            );
            if narrow {
                let form_left = qc.absolute_position().x;
                let form_right = form_left + qc.size().width;
                assert!(
                    form_left >= 23.5 && form_right <= window_width - 23.5,
                    "{label} narrow form margins are not centered/bounded: left={form_left}, right={form_right}"
                );
            }

            let (host, port, expected_port_width) = if narrow {
                assert!(find_by_id_opt(&h.ui, "QuickConnectForm::qc-host-port-row").is_none());
                find_by_id(&h.ui, "QuickConnectForm::qc-host-port-stack");
                (
                    find_by_id(&h.ui, "QuickConnectForm::qc-host-field-narrow"),
                    find_by_id(&h.ui, "QuickConnectForm::qc-port-field-narrow"),
                    120.0,
                )
            } else {
                assert!(find_by_id_opt(&h.ui, "QuickConnectForm::qc-host-port-stack").is_none());
                find_by_id(&h.ui, "QuickConnectForm::qc-host-port-row");
                (
                    find_by_id(&h.ui, "QuickConnectForm::qc-host-field"),
                    find_by_id(&h.ui, "QuickConnectForm::qc-port-field"),
                    100.0,
                )
            };

            let host_input = find_descendant_by_label(&host, "HOST");
            let port_input = find_descendant_by_label(&port, "PORT");
            assert_within(&host_input, &host, "Host input", "Host field");
            assert_within(&port_input, &port, "Port input", "Port field");
            assert!(
                (port.size().width - expected_port_width).abs() <= 0.5,
                "{label} Port width changed in narrow={narrow}: {:?}",
                port.size()
            );

            if narrow {
                let host_bottom = host.absolute_position().y + host.size().height;
                assert!(
                    host_bottom <= port.absolute_position().y + 0.5,
                    "{label} narrow Host must stack above Port"
                );
            } else {
                let host_right = host.absolute_position().x + host.size().width;
                assert!(
                    host_right <= port.absolute_position().x + 0.5,
                    "{label} wide Host overlaps Port"
                );
            }
        }
    }
}

// ── Profile editor (screens/profile_editor.slint::ProfileEditor) ───────────

/// A brand-new connection (`new_connection(0)`, the tree panel's "New
/// Connection" action) opens with the SSH default manifest: Host, Port=22,
/// Username present, no Domain/Resolution.
fn profile_editor_new_ssh_default_manifest() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    pump_ticks(1);
    assert!(
        h.ui.get_profile_editor_open(),
        "profile editor did not open"
    );

    let form = h.ui.get_profile_form();
    assert_eq!(form.kind, 0, "new connection defaults to SSH");
    assert_eq!(form.port.as_str(), "22", "SSH default port");

    find_by_id(&h.ui, "ProfileEditor::profile-host-field");
    find_by_id(&h.ui, "ProfileEditor::profile-username-field");
    assert!(find_by_id_opt(&h.ui, "ProfileEditor::profile-rdp-domain-field").is_none());
    assert!(find_by_id_opt(&h.ui, "ProfileEditor::profile-rdp-resolution-field").is_none());
}

/// RDP port-default regression scenario ("RDP port stuck at 22 / missing
/// Domain/Resolution"). Switching the profile
/// editor's kind selector to RDP must update the port default AND surface the
/// Domain/Resolution fields -- exactly the two symptoms of that defect.
///
/// The assertions cover the port update and RDP-only fields directly, so a
/// regression in either branch fails loudly.
fn profile_editor_kind_switch_updates_port_and_manifest() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    pump_ticks(1);

    let editor = find_singleton(&h.ui, "ProfileEditor");
    let rdp_tab = find_descendant_by_label(&editor, "RDP");
    rdp_tab.invoke_accessible_default_action();
    pump_ticks(1);

    let form = h.ui.get_profile_form();
    assert_eq!(form.kind, 1, "kind switch to RDP did not take");
    assert_eq!(
        form.port.as_str(),
        "3389",
        "kind switch to RDP must update the untouched port default (22 -> 3389)"
    );
    find_by_id(&h.ui, "ProfileEditor::profile-rdp-domain-field");
    find_by_id(&h.ui, "ProfileEditor::profile-rdp-resolution-field");
    find_by_id(&h.ui, "ProfileEditor::profile-host-field");
    find_by_id(&h.ui, "ProfileEditor::profile-username-field");
}

fn profile_editor_telnet_clears_credentials_and_saves_prompt() {
    let (h, repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    pump_ticks(1);

    // Seed stale SSH credential form state, then drive the real kind selector.
    let mut form = h.ui.get_profile_form();
    form.name = "Lab Telnet".into();
    form.host = "lab-switch".into();
    form.selected_cred_idx = 7;
    form.effective_cred_name = "stale credential".into();
    form.effective_cred_username = "stale-user".into();
    form.effective_inherited = true;
    form.cred_mode = 1;
    form.inline_password = "stale-secret".into();
    form.inline_has_secret = true;
    h.ui.set_profile_form(form);

    let editor = find_singleton(&h.ui, "ProfileEditor");
    find_descendant_by_label(&editor, "Telnet").invoke_accessible_default_action();
    pump_ticks(1);

    let form = h.ui.get_profile_form();
    assert_eq!(form.kind, 2);
    assert_eq!(form.port.as_str(), "23");
    assert_eq!(form.cred_mode, 2, "Telnet must force Prompt");
    assert_eq!(form.selected_cred_idx, 0);
    assert_eq!(form.effective_cred_name.as_str(), "");
    assert_eq!(form.effective_cred_username.as_str(), "");
    assert!(!form.effective_inherited);
    assert_eq!(form.inline_password.as_str(), "");
    assert!(!form.inline_has_secret);
    assert_eq!(form.username.as_str(), "");

    find_by_id(&h.ui, "ProfileEditor::profile-host-field");
    find_by_id(&h.ui, "ProfileEditor::profile-port-field");
    let warning = find_by_id(&h.ui, "ProfileEditor::profile-telnet-warning");
    assert_eq!(
        warning.accessible_label().as_deref(),
        Some("Telnet is unencrypted. Credentials and session data are sent in clear text.")
    );
    for absent in [
        "ProfileEditor::profile-username-field",
        "ProfileEditor::profile-username-readonly-field",
        "ProfileEditor::profile-cred-combo",
        "ProfileEditor::profile-inline-password-field",
        "ProfileEditor::profile-rdp-domain-field",
        "ProfileEditor::profile-rdp-resolution-field",
    ] {
        assert!(
            find_by_id_opt(&h.ui, absent).is_none(),
            "{absent} must not exist for Telnet"
        );
    }

    // Leaving Telnet starts from SSH's normal credential/default-port state.
    find_descendant_by_label(&editor, "SSH").invoke_accessible_default_action();
    pump_ticks(1);
    let away = h.ui.get_profile_form();
    assert_eq!(away.port.as_str(), "22");
    assert_eq!(away.cred_mode, 0);
    assert_eq!(away.selected_cred_idx, 0);

    // Return to Telnet, prove a typed non-default port is preserved, and save.
    h.ui.set_profile_form({
        let mut f = h.ui.get_profile_form();
        f.port = "2323".into();
        f
    });
    find_descendant_by_label(&editor, "Telnet").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_profile_form().port.as_str(), "2323");
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();

    let saved = repo.list_connections().expect("list_connections");
    let conn = saved
        .iter()
        .find(|c| c.name == "Lab Telnet")
        .expect("saved Telnet profile");
    assert!(matches!(conn.kind, cm_core::ConnectionKind::Telnet));
    assert!(matches!(
        conn.credential_source,
        Some(cm_core::CredentialSource::Prompt)
    ));
    match &conn.settings {
        cm_core::ConnectionSettings::Telnet(s) => {
            assert_eq!(s.host, "lab-switch");
            assert_eq!(s.port, 2323);
        }
        other => panic!("expected Telnet settings, got {other:?}"),
    }
}

/// A brand-new connection has no credential
/// assigned at all (`cred-mode` defaults to Reference/index-0-"Inherit",
/// `effective-cred-username` empty) -- the ordinary EDITABLE username field
/// must be present (it's the actual fallback that gets used), and the
/// read-only variant must not exist at all yet (behind a real `if`, not just
/// hidden).
fn profile_editor_new_connection_username_is_editable_with_no_credential() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    pump_ticks(1);

    let form = h.ui.get_profile_form();
    assert_eq!(form.cred_mode, 0, "new connection defaults to Reference");
    assert_eq!(
        form.effective_cred_username.as_str(),
        "",
        "no credential assigned yet"
    );
    find_by_id(&h.ui, "ProfileEditor::profile-username-field");
    assert!(find_by_id_opt(&h.ui, "ProfileEditor::profile-username-readonly-field").is_none());
}

/// Switching the mode selector to Inline swaps the credential picker for the
/// Inline password field; the ordinary editable username field stays (Inline
/// mode's own typed username is what's actually used).
fn profile_editor_inline_mode_shows_password_hides_credential_picker() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    pump_ticks(1);

    let editor = find_singleton(&h.ui, "ProfileEditor");
    find_descendant_by_label(&editor, "Inline").invoke_accessible_default_action();
    pump_ticks(1);

    let form = h.ui.get_profile_form();
    assert_eq!(form.cred_mode, 1, "mode switch to Inline did not take");
    find_by_id(&h.ui, "ProfileEditor::profile-username-field");
    find_by_id(&h.ui, "ProfileEditor::profile-inline-password-field");
    assert!(
        find_by_id_opt(&h.ui, "ProfileEditor::profile-cred-combo").is_none(),
        "Inline mode must hide the Reference-mode credential picker"
    );
}

/// "Prompt" must NOT be a selectable mode yet -- there
/// is no connect-time password-prompt UX to route into, so a Prompt
/// connection would surface a confusing "no credential assigned" error.
/// `CredentialSource::Prompt` stays in the model (harmless, unreachable);
/// this asserts the mode selector itself only ever offers Reference/Inline,
/// guarding against it being accidentally re-exposed.
fn profile_editor_credential_mode_selector_has_no_prompt_option() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    pump_ticks(1);

    let editor = find_singleton(&h.ui, "ProfileEditor");
    // Reference/Inline still exist and are switchable (exercised end to end
    // by the other mode-selector tests above); here just confirm Prompt
    // specifically does NOT exist in the tree at all -- not merely hidden.
    find_descendant_by_label(&editor, "Reference");
    find_descendant_by_label(&editor, "Inline");
    assert!(
        find_descendant_by_label_opt(&editor, "Prompt").is_none(),
        "Prompt must not be a selectable mode yet (no connect-time prompt UX exists)"
    );
}

/// A connection whose Reference credential HAS its own username
/// shows that username read-only (greyed) instead of the ordinary editable
/// field -- the credential's username is what's actually used
/// (`resolve_connection_auth`'s precedence), so editing the connection's own
/// field here would be misleading.
fn profile_editor_reference_mode_with_named_credential_is_read_only() {
    let (h, repo, _provider) = harness();

    // Create a credential with its own username via the real Keys-panel save
    // path (mirrors how a user would actually do this).
    h.ui.invoke_new_cred(0);
    pump_ticks(1);
    {
        let mut cred_form = h.ui.get_cred_form();
        cred_form.name = "Ops Admin".into();
        cred_form.username = "opsadmin".into();
        h.ui.set_cred_form(cred_form);
    }
    h.ui.invoke_cred_save();
    pump_ticks(1);

    // New connection, assign that credential (index 1 -- the only one, index
    // 0 is "Inherit"), save it.
    h.ui.invoke_new_connection(0);
    pump_ticks(1);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Ops Box".into();
        form.host = "10.0.0.9".into();
        form.selected_cred_idx = 1;
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
    pump_ticks(1);

    // Re-open it for edit: `wire_edit_conn` computes `effective-cred-username`
    // fresh from the reloaded connection (it isn't recomputed reactively as
    // the dropdown itself changes -- pre-existing behavior, unrelated to this
    // phase).
    let saved = repo.list_connections().expect("list_connections");
    let conn_id = saved
        .iter()
        .find(|c| c.name == "Ops Box")
        .expect("connection was saved")
        .id
        .get();
    h.ui.invoke_edit_conn(conn_id as i32);
    pump_ticks(1);

    let form = h.ui.get_profile_form();
    assert_eq!(form.cred_mode, 0, "Reference mode (Object credential)");
    assert_eq!(form.effective_cred_username.as_str(), "opsadmin");
    find_by_id(&h.ui, "ProfileEditor::profile-username-readonly-field");
    assert!(
        find_by_id_opt(&h.ui, "ProfileEditor::profile-username-field").is_none(),
        "the editable username field must not exist while the read-only one does"
    );
}

/// Save persists the typed fields to the repo and closes the dialog; a
/// second connection, edited and then Cancelled, must never reach the repo.
fn profile_editor_save_persists_and_cancel_discards() {
    let (h, repo, _provider) = harness();

    // -- Save persists --------------------------------------------------
    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Test Save".into();
        form.host = "10.1.2.3".into();
        form.username = "ops".into();
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();

    assert!(
        !h.ui.get_profile_editor_open(),
        "Save must close the profile editor"
    );
    let saved = repo.list_connections().expect("list_connections");
    assert_eq!(saved.len(), 1, "Save must persist exactly one connection");
    assert_eq!(saved[0].name, "Test Save");

    // -- Cancel discards --------------------------------------------------
    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Should Not Persist".into();
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-cancel-btn").invoke_accessible_default_action();

    assert!(
        !h.ui.get_profile_editor_open(),
        "Cancel must close the profile editor"
    );
    let after_cancel = repo.list_connections().expect("list_connections");
    assert_eq!(
        after_cancel.len(),
        1,
        "Cancel must not persist a second connection"
    );
    assert!(after_cancel.iter().all(|c| c.name != "Should Not Persist"));
}

/// Save and a fresh Open already
/// clear the transient Inline password (secrets hygiene) -- Cancel must too,
/// or a typed-then-cancelled password lingers in `profile-form` until the
/// next editor-open.
fn profile_editor_cancel_clears_the_transient_inline_password() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    pump_ticks(1);
    {
        let mut form = h.ui.get_profile_form();
        form.inline_password = "hunter2".into();
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-cancel-btn").invoke_accessible_default_action();

    assert_eq!(
        h.ui.get_profile_form().inline_password.as_str(),
        "",
        "Cancel must clear the transient Inline password, not just Save/Open"
    );
}

// ── Geometry (dialog/button bounds) ─────────────────

/// A short Telnet form must consume only its preferred height, while a
/// long RDP form must be wheel-scrollable through its final control without
/// the fixed action footer covering it.
fn profile_editor_fields_stay_packed_and_scroll_clear_of_footer() {
    let (h, _repo, _provider) = harness();
    h.ui.window()
        .set_size(slint::LogicalSize::new(900.0, 600.0));
    h.ui.invoke_new_connection(0);
    pump_ticks(1);

    let editor = find_singleton(&h.ui, "ProfileEditor");
    find_descendant_by_label(&editor, "Telnet").invoke_accessible_default_action();
    pump_ticks(1);

    let name = find_by_id(&h.ui, "ProfileEditor::profile-name-field");
    let host = find_by_id(&h.ui, "ProfileEditor::profile-host-field");
    let port = find_by_id(&h.ui, "ProfileEditor::profile-port-field");
    for (label, field) in [("Name", name), ("Host", host), ("Port", port)] {
        assert!(
            field.size().height <= 64.0,
            "Telnet {label} field stretched beyond the established control stack: {:?}",
            field.size()
        );
    }

    find_descendant_by_label(&editor, "RDP").invoke_accessible_default_action();
    pump_ticks(1);

    let scroll = find_by_id(&h.ui, "ProfileEditor::profile-fields-scroll");
    let footer = find_by_id(&h.ui, "ProfileEditor::profile-cancel-btn");
    let scroll_bottom = scroll.absolute_position().y + scroll.size().height;
    assert!(
        scroll_bottom <= footer.absolute_position().y + 0.5,
        "the field viewport must end above the fixed footer"
    );

    let mut resolution = find_by_id_opt(&h.ui, "ProfileEditor::profile-rdp-resolution-field");
    for _ in 0..12 {
        let fully_visible = resolution.as_ref().is_some_and(|field| {
            field.absolute_position().y >= scroll.absolute_position().y - 0.5
                && field.absolute_position().y + field.size().height <= scroll_bottom + 0.5
        });
        if fully_visible {
            break;
        }
        scroll.scroll(0.0, -80.0);
        pump_ticks(1);
        resolution = find_by_id_opt(&h.ui, "ProfileEditor::profile-rdp-resolution-field");
    }
    let resolution = resolution.expect("RDP Resolution must become visible by wheel-scrolling");
    assert!(
        resolution.size().height <= 64.0,
        "RDP Resolution field stretched beyond the established control stack: {:?}",
        resolution.size()
    );
    assert!(
        resolution.absolute_position().y + resolution.size().height <= scroll_bottom + 0.5,
        "RDP Resolution must scroll fully above the footer"
    );

    for _ in 0..12 {
        scroll.scroll(0.0, -160.0);
        pump_ticks(1);
    }
    let final_control = find_by_id(&h.ui, "ProfileEditor::profile-cred-combo");
    let gap = scroll_bottom - (final_control.absolute_position().y + final_control.size().height);
    assert!(
        gap >= 20.0,
        "long-form bottom padding must remain visible after the final control; gap={gap}"
    );
}

/// Deterministic WCAG contrast checks against the live Slint tokens.
fn semantic_foregrounds_meet_normal_text_contrast() {
    let probe = ThemeProbe::new().expect("construct ThemeProbe");
    for dark_mode in [false, true] {
        probe.set_dark_mode(dark_mode);
        let surfaces = [
            ("overlay", probe.get_overlay()),
            ("card", probe.get_card()),
            ("elevated", probe.get_elevated()),
            ("base", probe.get_base()),
        ];
        for (semantic, foreground) in [
            ("connecting", probe.get_connecting_foreground()),
            ("error", probe.get_error_foreground()),
        ] {
            for (surface_name, surface) in surfaces {
                let ratio = contrast_ratio(foreground, surface);
                assert!(
                    ratio >= 4.5,
                    "{semantic} foreground has only {ratio:.2}:1 contrast on {surface_name} (dark_mode={dark_mode})"
                );
            }
        }
    }
}

fn contrast_ratio(a: slint::Color, b: slint::Color) -> f64 {
    fn luminance(color: slint::Color) -> f64 {
        let rgba = color.to_argb_u8();
        let linear = |component: u8| {
            let value = f64::from(component) / 255.0;
            if value <= 0.04045 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(rgba.red) + 0.7152 * linear(rgba.green) + 0.0722 * linear(rgba.blue)
    }

    let a = luminance(a);
    let b = luminance(b);
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// Save/Cancel sit within the dialog's own bounds, and the dialog sits
/// within the window's bounds -- logical-pixel assertions on
/// `absolute_position()` + `size()` ensure that a dialog cannot exceed its
/// parent window.
fn dialog_and_button_bounds() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_new_connection(0);

    let window_size = h.ui.root_element().size();
    let dialog = find_singleton(&h.ui, "ProfileEditor");
    assert_within(
        &dialog,
        &h.ui.root_element(),
        "ProfileEditor dialog",
        "window",
    );
    assert!(
        dialog.size().width <= window_size.width && dialog.size().height <= window_size.height,
        "ProfileEditor dialog ({:?}) must not exceed the window ({window_size:?})",
        dialog.size()
    );

    let save_btn = find_by_id(&h.ui, "ProfileEditor::profile-save-btn");
    let cancel_btn = find_by_id(&h.ui, "ProfileEditor::profile-cancel-btn");
    assert_within(&save_btn, &dialog, "Save button", "ProfileEditor dialog");
    assert_within(
        &cancel_btn,
        &dialog,
        "Cancel button",
        "ProfileEditor dialog",
    );

    // Same check on the quick-connect dialog's Connect/Cancel (mirrors the
    // profile editor's; quick-connect had no separate historical defect but
    // the check costs nothing extra and covers the other dialog family).
    h.ui.set_profile_editor_open(false);
    h.ui.invoke_quick_connect();
    let qc = find_singleton(&h.ui, "QuickConnectForm");
    assert_within(
        &qc,
        &h.ui.root_element(),
        "QuickConnectForm dialog",
        "window",
    );
    let connect_btn = find_by_id(&h.ui, "QuickConnectForm::qc-connect-btn");
    let qc_cancel_btn = find_by_id(&h.ui, "QuickConnectForm::qc-cancel-btn");
    assert_within(
        &connect_btn,
        &qc,
        "Connect button",
        "QuickConnectForm dialog",
    );
    assert_within(
        &qc_cancel_btn,
        &qc,
        "Cancel button",
        "QuickConnectForm dialog",
    );
}

/// Geometry coverage for `CredTreeRow`, the Keys panel's hover-icon
/// click fix): after moving `touch` into its own `content` cell,
/// `ConnectionRow`'s `269a5e5` fix exactly), the row's activate path and its
/// accessible attributes -- which stayed on the `CredTreeRow` ROOT rather
/// than moving into `content`, per the port's own explicit instruction --
/// must be unchanged. The real-pointer hover-icon click this port actually
/// pointer-coordinate synthesis is unavailable in this harness; this proves
/// the structural
/// refactor didn't regress the one thing this suite CAN drive: the row's
/// own click/accessible-default-action activation and its a11y label/
/// selection state.
fn cred_row_activate_and_a11y_survive_the_content_cell_restructure() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_select_panel(1); // Keys panel
    pump_ticks(1);

    h.ui.invoke_new_cred(0);
    pump_ticks(1);
    {
        let mut cred_form = h.ui.get_cred_form();
        cred_form.name = "Row Restructure Target".into();
        h.ui.set_cred_form(cred_form);
    }
    h.ui.invoke_cred_save();
    pump_ticks(1);

    let row = nth_by_id(&h.ui, "AppWindow::cred-row", 0);
    assert_eq!(
        row.accessible_label().as_deref(),
        Some("Row Restructure Target"),
        "the a11y label (kept on the CredTreeRow root, not moved into `content`) \
         must still expose the credential's name"
    );
    assert_eq!(
        row.accessible_item_selected(),
        Some(false),
        "a freshly-created row starts unselected"
    );

    assert!(
        !h.ui.get_cred_editor_open(),
        "seed: the credential editor is closed before activation"
    );
    row.invoke_accessible_default_action();
    pump_ticks(1);
    assert!(
        h.ui.get_cred_editor_open(),
        "the row's accessible-default-action (mirrors a real click on `touch`, \
         now scoped inside `content`) must still activate -- open the credential editor"
    );
}

/// Asserts `inner`'s bounding box is fully contained within `outer`'s, in
/// window-absolute logical-pixel coordinates.
fn assert_within(inner: &ElementHandle, outer: &ElementHandle, inner_name: &str, outer_name: &str) {
    let ip = inner.absolute_position();
    let is = inner.size();
    let op = outer.absolute_position();
    let os = outer.size();
    assert!(
        ip.x >= op.x - 0.5
            && ip.y >= op.y - 0.5
            && ip.x + is.width <= op.x + os.width + 0.5
            && ip.y + is.height <= op.y + os.height + 0.5,
        "{inner_name} (pos {ip:?}, size {is:?}) must sit within {outer_name} (pos {op:?}, size {os:?})"
    );
}
