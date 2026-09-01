//! Saved profiles keep their user-facing names in the tab strip.
//! and active-session label. Quick Connect remains endpoint-derived.

#![cfg(feature = "ui-introspection")]

mod support;

use cm_ui::AppWindow;
use slint::Model;

use support::{find_by_id, harness, pump_ticks};

#[test]
fn saved_titles_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    saved_profile_names_cover_every_protocol_and_survive_lifecycle();
    quick_connect_keeps_generated_labels();
}

fn save_profile(ui: &AppWindow, name: &str, kind: i32, host: &str, port: &str) {
    ui.invoke_new_connection(0);
    let mut form = ui.get_profile_form();
    form.name = name.into();
    form.kind = kind;
    form.host = host.into();
    form.port = port.into();
    match kind {
        0 => {
            form.username = "synthetic-user".into();
            form.auth_method = 2; // Agent: no stored secret required.
        }
        1 => {
            form.username = "synthetic-user".into();
            form.cred_mode = 2; // Prompt: title behavior also covers auth-failure tabs.
        }
        2 => {
            form.cred_mode = 2;
        }
        3 => {}
        _ => unreachable!("unsupported profile kind"),
    }
    ui.set_profile_form(form);
    find_by_id(ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
}

fn activate_saved(ui: &AppWindow, name: &str) -> usize {
    let rows = ui.get_connections();
    let idx = (0..rows.row_count())
        .find(|&idx| {
            rows.row_data(idx)
                .is_some_and(|row| !row.is_group && row.label.as_str() == name)
        })
        .unwrap_or_else(|| panic!("saved profile {name:?} not present in connection tree"));
    ui.invoke_row_activated(idx as i32);
    pump_ticks(1);
    ui.get_active_tab() as usize
}

fn assert_active_label(ui: &AppWindow, tab_idx: usize, expected: &str) {
    assert_eq!(ui.get_active_tab(), tab_idx as i32);
    assert_eq!(
        ui.get_tabs()
            .row_data(tab_idx)
            .expect("active tab row")
            .title
            .as_str(),
        expected,
        "tab strip must use the selected display label"
    );
    assert_eq!(
        ui.get_session_identity().as_str(),
        expected,
        "active-session label must match the tab's selected display label"
    );
}

fn saved_profile_names_cover_every_protocol_and_survive_lifecycle() {
    let (h, _repo, provider) = harness();

    save_profile(&h.ui, "Named Local", 3, "", "");
    save_profile(&h.ui, "Named SSH", 0, "saved-ssh.example.invalid", "22");
    save_profile(&h.ui, "Named RDP", 1, "saved-rdp.example.invalid", "3389");
    save_profile(
        &h.ui,
        "Named Telnet",
        2,
        "saved-telnet.example.invalid",
        "23",
    );

    let local_idx = activate_saved(&h.ui, "Named Local");
    assert_active_label(&h.ui, local_idx, "Named Local");

    let ssh_idx = activate_saved(&h.ui, "Named SSH");
    assert_active_label(&h.ui, ssh_idx, "Named SSH");
    assert_eq!(provider.ssh_connect_count(), 1);

    // Reconnect used to overwrite the cached active-session label with the
    // generated user@host endpoint even though the tab itself stayed named.
    h.ui.invoke_tab_reconnect(ssh_idx as i32);
    pump_ticks(1);
    assert_eq!(provider.ssh_connect_count(), 2);
    assert_active_label(&h.ui, ssh_idx, "Named SSH");

    let rdp_idx = activate_saved(&h.ui, "Named RDP");
    assert_active_label(&h.ui, rdp_idx, "Named RDP");

    let telnet_idx = activate_saved(&h.ui, "Named Telnet");
    assert_active_label(&h.ui, telnet_idx, "Named Telnet");
    assert_eq!(provider.telnet_connect_count(), 1);

    h.ui.invoke_tab_reconnect(telnet_idx as i32);
    pump_ticks(1);
    assert_eq!(provider.telnet_connect_count(), 2);
    assert_active_label(&h.ui, telnet_idx, "Named Telnet");

    // A plain tab switch must republish the saved label from Tab::identity.
    h.ui.invoke_select_tab(0);
    h.ui.invoke_select_tab(ssh_idx as i32);
    assert_active_label(&h.ui, ssh_idx, "Named SSH");
}

fn quick_connect_keeps_generated_labels() {
    let (h, _repo, provider) = harness();

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(0);
    h.ui.set_qc_host("quick-ssh.example.invalid".into());
    h.ui.set_qc_port("2222".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_auth_method(2); // Agent.
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    let ssh_idx = h.ui.get_active_tab() as usize;
    assert_eq!(
        h.ui.get_tabs().row_data(ssh_idx).unwrap().title.as_str(),
        "SSH quick-ssh.example.invalid"
    );
    assert_eq!(
        h.ui.get_session_identity().as_str(),
        "synthetic-user@quick-ssh.example.invalid:2222"
    );

    h.ui.invoke_tab_reconnect(ssh_idx as i32);
    pump_ticks(1);
    assert_eq!(provider.ssh_connect_count(), 2);
    assert_eq!(
        h.ui.get_session_identity().as_str(),
        "synthetic-user@quick-ssh.example.invalid:2222",
        "Quick Connect reconnect must retain its generated endpoint label"
    );

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(1);
    h.ui.set_qc_host("quick-rdp.example.invalid".into());
    h.ui.set_qc_port("3390".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_secret("synthetic-password".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    let rdp_idx = h.ui.get_active_tab() as usize;
    assert_eq!(
        h.ui.get_tabs().row_data(rdp_idx).unwrap().title.as_str(),
        "RDP quick-rdp.example.invalid"
    );
    assert_eq!(
        h.ui.get_session_identity().as_str(),
        "synthetic-user@quick-rdp.example.invalid:3390"
    );

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(2);
    h.ui.set_qc_host("quick-telnet.example.invalid".into());
    h.ui.set_qc_port("2323".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    let telnet_idx = h.ui.get_active_tab() as usize;
    assert_eq!(
        h.ui.get_tabs().row_data(telnet_idx).unwrap().title.as_str(),
        "TELNET quick-telnet.example.invalid"
    );
    assert_eq!(
        h.ui.get_session_identity().as_str(),
        "quick-telnet.example.invalid:2323"
    );

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(3);
    h.ui.set_qc_local_program("".into());
    h.ui.set_qc_local_args("".into());
    h.ui.set_qc_local_cwd("".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    let local_idx = h.ui.get_active_tab() as usize;
    let title = h.ui.get_tabs().row_data(local_idx).unwrap().title;
    assert!(title.starts_with("shell "), "got {title:?}");
    assert_eq!(h.ui.get_session_identity(), title);
}
