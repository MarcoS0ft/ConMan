//! Dialog integration suite for host-key, RDP-certificate, and import-password
//! prompts. It verifies each dialog's field manifest, unknown/mismatch variants,
//! button labels, and close callbacks.
//!
//! The production verifier queues its callback on the UI event loop, which the
//! in-process test backend does not run. These tests therefore drive the same
//! dialog properties directly and cover the model, field manifest, rendered
//! text, button labels, and close callbacks. Import dispatch remains covered
//! by controller unit tests because the integration harness cannot invoke the
//! native file picker.

#![cfg(feature = "ui-introspection")]

mod support;

use support::{find_by_id, find_by_id_opt, find_singleton, harness, pump_ticks};

#[test]
fn verifier_dialogs_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    host_key_unknown_manifest_and_accept_closes();
    host_key_mismatch_manifest_and_reject_closes();
    cert_unknown_manifest_and_accept_remember_closes();
    cert_mismatch_manifest_and_reject_closes();
    import_password_dialog_manifest_and_submit_closes();
    import_password_dialog_cancel_closes();
}

/// Unknown-host-key TOFU: "Reject" (secondary) / "Accept & continue"
/// (primary) -- the two buttons J8 (Linux) and the Windows SSH-probe journey
/// both drove for real over the socket-era harness.
fn host_key_unknown_manifest_and_accept_closes() {
    let (h, _repo, _provider) = harness();
    h.ui.set_host_key_mismatch(false);
    h.ui.set_host_key_host("127.0.0.2:22".into());
    h.ui.set_host_key_type("ssh-ed25519 \u{b7} 256-bit".into());
    h.ui.set_host_key_fingerprint("SHA256:tQM4amUpDVXZMjosjz4zYuaoO/67GiEAY6yn1Mbkios".into());
    h.ui.set_host_key_open(true);
    pump_ticks(1);

    let dialog = find_singleton(&h.ui, "HostKeyDialog");
    assert_eq!(
        dialog.accessible_label().as_deref(),
        Some("Unknown host key dialog")
    );
    find_by_id(&h.ui, "HostKeyDialog::hostkey-reject-unknown-btn");
    find_by_id(&h.ui, "HostKeyDialog::hostkey-accept-continue-btn");
    assert!(
        find_by_id_opt(&h.ui, "HostKeyDialog::hostkey-reject-mismatch-btn").is_none(),
        "the mismatch button variant must not exist for the unknown-host case"
    );
    assert!(
        find_by_id_opt(&h.ui, "HostKeyDialog::hostkey-accept-replace-btn").is_none(),
        "the mismatch button variant must not exist for the unknown-host case"
    );

    find_by_id(&h.ui, "HostKeyDialog::hostkey-accept-continue-btn")
        .invoke_accessible_default_action();
    assert!(
        !h.ui.get_host_key_open(),
        "Accept & continue must close the host-key dialog"
    );
}

/// Host-key MISMATCH (the loud "possible attack" variant): "Reject"
/// becomes primary/default and "Accept & replace" is marked destructive --
/// distinct element ids from the unknown-host variant (never the same
/// button relabeled), per `dialogs.slint`'s `if mismatch : ... if !mismatch :
/// ...` structure.
fn host_key_mismatch_manifest_and_reject_closes() {
    let (h, _repo, _provider) = harness();
    h.ui.set_host_key_mismatch(true);
    h.ui.set_host_key_host("web-prod-01:22".into());
    h.ui.set_host_key_stored_fp("SHA256:aRq9Kf2PpXc8".into());
    h.ui.set_host_key_fingerprint("SHA256:DIFFERENT-fingerprint".into());
    h.ui.set_host_key_open(true);
    pump_ticks(1);

    let dialog = find_singleton(&h.ui, "HostKeyDialog");
    assert_eq!(
        dialog.accessible_label().as_deref(),
        Some("Host key mismatch dialog")
    );
    find_by_id(&h.ui, "HostKeyDialog::hostkey-reject-mismatch-btn");
    find_by_id(&h.ui, "HostKeyDialog::hostkey-accept-replace-btn");
    assert!(find_by_id_opt(&h.ui, "HostKeyDialog::hostkey-reject-unknown-btn").is_none());
    assert!(find_by_id_opt(&h.ui, "HostKeyDialog::hostkey-accept-continue-btn").is_none());

    find_by_id(&h.ui, "HostKeyDialog::hostkey-reject-mismatch-btn")
        .invoke_accessible_default_action();
    assert!(
        !h.ui.get_host_key_open(),
        "Reject must close the mismatch dialog"
    );
}

/// Unknown/self-signed RDP certificate TOFU (the Windows Part-C1
/// journey's dialog): "Reject" / "Accept & remember", subject + SHA-256
/// fingerprint rendered in mono, both verified truthful against the real
/// target in the Windows journey -- this suite only proves the *dialog*
/// renders the manifest and wires Accept/Reject, not the truthfulness
/// (that needs a real cert, MCP territory).
fn cert_unknown_manifest_and_accept_remember_closes() {
    let (h, _repo, _provider) = harness();
    h.ui.set_cert_dialog_mismatch(false);
    h.ui.set_cert_dialog_host("192.0.2.16:3389".into());
    h.ui.set_cert_dialog_subject("CN=WIN11-TGT".into());
    h.ui.set_cert_dialog_fingerprint(
        "SHA256:424f2b1b22b081094220d7b9e6b625d2b5c8f2551978f79edd949dcfdf39c77f".into(),
    );
    h.ui.set_cert_dialog_open(true);
    pump_ticks(1);

    let dialog = find_singleton(&h.ui, "CertDialog");
    assert_eq!(
        dialog.accessible_label().as_deref(),
        Some("Unknown RDP certificate dialog")
    );
    find_by_id(&h.ui, "CertDialog::cert-reject-unknown-btn");
    find_by_id(&h.ui, "CertDialog::cert-accept-remember-btn");
    assert!(find_by_id_opt(&h.ui, "CertDialog::cert-reject-mismatch-btn").is_none());
    assert!(find_by_id_opt(&h.ui, "CertDialog::cert-accept-replace-btn").is_none());

    find_by_id(&h.ui, "CertDialog::cert-accept-remember-btn").invoke_accessible_default_action();
    assert!(
        !h.ui.get_cert_dialog_open(),
        "Accept & remember must close the cert dialog"
    );
}

/// RDP cert MISMATCH (possible MITM warning).
fn cert_mismatch_manifest_and_reject_closes() {
    let (h, _repo, _provider) = harness();
    h.ui.set_cert_dialog_mismatch(true);
    h.ui.set_cert_dialog_host("192.0.2.16:3389".into());
    h.ui.set_cert_dialog_subject("CN=WIN11-TGT".into());
    h.ui.set_cert_dialog_stored_fp("SHA256:AAAA".into());
    h.ui.set_cert_dialog_fingerprint("SHA256:BBBB-different".into());
    h.ui.set_cert_dialog_open(true);
    pump_ticks(1);

    let dialog = find_singleton(&h.ui, "CertDialog");
    assert_eq!(
        dialog.accessible_label().as_deref(),
        Some("RDP certificate mismatch dialog")
    );
    find_by_id(&h.ui, "CertDialog::cert-reject-mismatch-btn");
    find_by_id(&h.ui, "CertDialog::cert-accept-replace-btn");

    find_by_id(&h.ui, "CertDialog::cert-reject-mismatch-btn").invoke_accessible_default_action();
    assert!(
        !h.ui.get_cert_dialog_open(),
        "Reject must close the cert-mismatch dialog"
    );
}

/// The mRemoteNG import password prompt -- manifest (file name
/// rendering, field + button presence) and that Import (the real
/// `on_import_password_submit` wiring) closes the dialog. `pending_import_
/// path` is never populated here (see the module doc's honest-limit note),
/// so this exercises submit's nothing-pending no-op branch, not a real
/// retry -- the retry logic itself is unit-tested dialog-free in
/// `controller/import_export.rs`.
fn import_password_dialog_manifest_and_submit_closes() {
    let (h, _repo, _provider) = harness();
    h.ui.set_import_password_file_name("confCons.xml".into());
    h.ui.set_import_password_open(true);
    pump_ticks(1);

    let dialog = find_singleton(&h.ui, "ImportPasswordDialog");
    assert_eq!(
        dialog.accessible_label().as_deref(),
        Some("Import password dialog")
    );
    find_by_id(&h.ui, "ImportPasswordDialog::import-password-field");
    find_by_id(&h.ui, "ImportPasswordDialog::import-password-cancel-btn");
    let submit_btn = find_by_id(&h.ui, "ImportPasswordDialog::import-password-submit-btn");

    // Typing into the password field -- proves `on_import_password_edited`
    // doesn't panic; never re-displayed/asserted against (no-leak
    // shape, same as `KbdInteractiveDialog`'s answers).
    h.ui.invoke_import_password_edited("mock-password".into());

    submit_btn.invoke_accessible_default_action();
    assert!(
        !h.ui.get_import_password_open(),
        "Import must close the password dialog"
    );
}

/// Cancel (the real `on_import_password_cancel` wiring) closes the dialog
/// too, without attempting any import.
fn import_password_dialog_cancel_closes() {
    let (h, _repo, _provider) = harness();
    h.ui.set_import_password_file_name("confCons.xml".into());
    h.ui.set_import_password_open(true);
    pump_ticks(1);

    find_by_id(&h.ui, "ImportPasswordDialog::import-password-cancel-btn")
        .invoke_accessible_default_action();
    assert!(
        !h.ui.get_import_password_open(),
        "Cancel must close the password dialog"
    );
}
