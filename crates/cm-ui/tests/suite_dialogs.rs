//! P8.2 Suite 1 — dialogs: quick-connect + profile-editor field manifests per
//! kind, kind-switch port defaults, Save/Cancel persistence, and dialog/button
//! geometry. Covers the P6.17 "New connection" / "Edit connection" / "Quick
//! connect" journeys and is exactly the check the win-ui memo's §A/§B said
//! "would have caught" defect #2 (RDP port stuck at 22, missing Domain/
//! Resolution) outright.
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

use support::{
    find_by_id, find_by_id_opt, find_descendant_by_label, find_descendant_by_label_opt,
    find_singleton, harness, pump_ticks,
};

#[test]
fn dialogs_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    quick_connect_ssh_default_manifest();
    quick_connect_rdp_manifest_and_kind_switch();
    quick_connect_local_manifest();
    profile_editor_new_ssh_default_manifest();
    profile_editor_kind_switch_updates_port_and_manifest();
    profile_editor_new_connection_username_is_editable_with_no_credential();
    profile_editor_inline_mode_shows_password_hides_credential_picker();
    profile_editor_credential_mode_selector_has_no_prompt_option();
    profile_editor_reference_mode_with_named_credential_is_read_only();
    profile_editor_save_persists_and_cancel_discards();
    profile_editor_cancel_clears_the_transient_inline_password();
    dialog_and_button_bounds();
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

    assert_eq!(h.ui.get_qc_kind(), 2);
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

/// THE TEETH SCENARIO for defect #2 ("RDP port stuck at 22 / missing
/// Domain/Resolution", `docs/devel/p8-plan.md` table). Switching the profile
/// editor's kind selector to RDP must update the port default AND surface the
/// Domain/Resolution fields -- exactly the two symptoms of that defect.
///
/// Verification note (see the P8.2 task report): this scenario was run
/// against a locally-reintroduced regression (the `changed(new-kind)` port
/// handler removed and the RDP-only fields deleted from
/// `screens/profile_editor.slint`) to confirm it fails loudly, then reverted
/// -- the tree at `master`/this branch already has the fix, so the assertions
/// below pass unconditionally in every normal run.
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
        "defect #2: kind switch to RDP must update the untouched port default (22 -> 3389)"
    );
    find_by_id(&h.ui, "ProfileEditor::profile-rdp-domain-field");
    find_by_id(&h.ui, "ProfileEditor::profile-rdp-resolution-field");
    find_by_id(&h.ui, "ProfileEditor::profile-host-field");
    find_by_id(&h.ui, "ProfileEditor::profile-username-field");
}

/// P9.6-A Phase C (P9.5 #7): a brand-new connection has no credential
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

/// Per Fable's guidance: "Prompt" must NOT be a selectable mode yet -- there
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

/// P9.5 #6/#7: a connection whose Reference credential HAS its own username
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

/// Fable non-blocking note (P9.6-A Phase C): Save and a fresh Open already
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

// ── Geometry (P6.17 gap #1's sibling: dialog/button bounds) ─────────────────

/// Save/Cancel sit within the dialog's own bounds, and the dialog sits
/// within the window's bounds -- logical-pixel assertions on
/// `absolute_position()` + `size()`, the exact check the win-ui memo's §A/§B
/// said would have caught a mispositioned/oversized dialog.
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
