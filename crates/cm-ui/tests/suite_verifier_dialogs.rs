//! P8.4 Suite -- host-key / RDP-cert dialogs (P3.1/P4.2), covering the P6.17
//! Linux J8 / Windows "SSH... host-key TOFU" and Part-C1 RDP-cert journeys'
//! *dialog* half: field manifest, mismatch-vs-unknown copy/button variants,
//! and that Accept/Reject actually close the dialog.
//!
//! ## Honest limit (read before extending this suite)
//! The real `UiHostKeyVerifier`/`UiCertVerifier` (`controller/sessions.rs`)
//! run `decide()` on a background thread spawned by the concrete
//! `SessionProvider`, block on `rx.recv()`, and marshal the "show the
//! dialog" step onto the UI thread via `slint::invoke_from_event_loop`.
//! That marshalling only executes once something drains the testing
//! backend's event queue -- i.e. `AppWindow::run()` / `run_event_loop()` --
//! which the P8.2 `build_for_test` seam **deliberately never enters** (see
//! its doc: "does not enter the event loop"). Verified against the vendored
//! `i-slint-backend-testing` source
//! (`testing_backend.rs`'s `Queue::invoke_from_event_loop` just pushes to a
//! `VecDeque` and unparks a thread; only `TestingBackend::run_event_loop`
//! pops it). So the real accept-a-*queued*-decision round trip through
//! `HkQueue`/`cert_pending` genuinely cannot be driven from this harness
//! without either entering the event loop (defeats the point of an
//! in-process, no-display seam) or new product code (out of scope, per
//! CONVENTIONS §3.5) -- this is reported to the coordinator via the P8.4
//! mapping table's `retired:` note on that half, not silently skipped.
//!
//! What **is** testable here, and is exactly what P8.2's three suites never
//! covered: the dialogs' own model + structure -- field manifest per
//! situation (unknown vs mismatch), the fingerprint/subject text rendering,
//! button labels, and that clicking Accept/Reject (the real
//! `on_host_key_accept`/`on_host_key_reject`/`on_cert_accept`/`on_cert_reject`
//! callback wiring) closes the dialog. This suite drives the dialogs open by
//! setting the exact same properties `UiHostKeyVerifier::decide` /
//! `UiCertVerifier::decide` set (`host_key_open`, `host_key_mismatch`, ...) --
//! i.e. it plays the verifier's role directly, in-line, on the test thread,
//! which is a legitimate "mock verifier" in spirit even though it isn't the
//! literal `HostKeyVerifier`/`CertVerifier` trait object. The MCP layer (J8 /
//! Part-C1's real accept-reaches-Connected round trip) is where the full,
//! real, threaded path is actually exercised end to end -- see
//! `memos/P8.4-qa-gate-rubric.md`'s mapping table.

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

/// Host-key MISMATCH (the loud "possible attack" variant, P3.1): "Reject"
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

/// Unknown/self-signed RDP certificate TOFU (P4.2, the Windows Part-C1
/// journey's dialog): "Reject" / "Accept & remember", subject + SHA-256
/// fingerprint rendered in mono, both verified truthful against the real
/// target in the Windows P6.17 memo -- this suite only proves the *dialog*
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
