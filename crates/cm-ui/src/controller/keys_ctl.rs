//! Keys (credentials) panel: CRUD for credentials/folders and the
//! index<->id resolution helpers used by both this panel and the profile form.
use std::rc::Rc;

use cm_core::{
    Credential, CredentialFolder, CredentialFolderId, CredentialId, CredentialKind,
    CredentialPurpose, CredentialRef, Secret,
};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::keys::KeysPanel;
use crate::tree::build_cred_name_list;
use crate::{AppWindow, CredRow};

use crate::generated_ui::CredFormData;

use super::*;

pub(super) fn wire_keys_ctl(ctx: &Ctx) {
    wire_cred_filter_changed(ctx);
    wire_toggle_cred_row(ctx);
    wire_new_cred(ctx);
    wire_new_cred_folder(ctx);
    wire_edit_cred(ctx);
    wire_delete_cred_row(ctx);
    wire_cred_save(ctx);
}

fn wire_cred_filter_changed(ctx: &Ctx) {
    ctx.ui.on_cred_filter_changed({
        let state = ctx.state.clone();
        let cred_model = ctx.cred_model.clone();
        move |q| {
            let mut st = state.borrow_mut();
            st.cred_filter = q.to_string();
            refresh_cred_model(&st, &cred_model);
        }
    });
}

fn wire_toggle_cred_row(ctx: &Ctx) {
    ctx.ui.on_toggle_cred_row({
        let state = ctx.state.clone();
        let cred_model = ctx.cred_model.clone();
        move |idx| {
            let mut st = state.borrow_mut();
            let flat = st.keys_panel.flat();
            if let Some(row) = flat.get(idx as usize)
                && row.is_folder
            {
                st.keys_panel.toggle_expand(row.id as i64);
                refresh_cred_model(&st, &cred_model);
            }
        }
    });
}

fn wire_new_cred(ctx: &Ctx) {
    ctx.ui.on_new_cred({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |folder_id| {
            let Some(ui) = weak.upgrade() else { return };
            // Resolve the DB folder id to a combo index so the picker
            // pre-selects the folder from which the "New Credential" action
            // was triggered.
            let selected_folder_idx = {
                let st = state.borrow();
                let fid = if folder_id == 0 {
                    None
                } else {
                    Some(CredentialFolderId::new(folder_id as i64))
                };
                folder_name_idx(fid, st.keys_panel.folders())
            };
            let form = CredFormData {
                id: 0,
                name: SharedString::from("New Credential"),
                kind: 0,
                username: SharedString::from(""),
                folder_id,
                selected_folder_idx,
                secret: SharedString::from(""),
                passphrase: SharedString::from(""),
            };
            ui.set_cred_form(form);
            ui.set_cred_editor_open(true);
        }
    });
}

fn wire_new_cred_folder(ctx: &Ctx) {
    ctx.ui.on_new_cred_folder({
        let state = ctx.state.clone();
        let cred_model = ctx.cred_model.clone();
        let repo_ncf = ctx.repo.clone();
        let weak = ctx.ui.as_weak();
        move |parent_folder_id| {
            let Some(_ui) = weak.upgrade() else { return };
            let fid = if parent_folder_id == 0 {
                None
            } else {
                Some(CredentialFolderId::new(parent_folder_id as i64))
            };
            let sort = {
                let st = state.borrow();
                st.keys_panel
                    .folders()
                    .iter()
                    .filter(|f| f.parent_id == fid)
                    .map(|f| f.sort)
                    .max()
                    .map(|m| m + 1)
                    .unwrap_or(0)
            };
            let folder = CredentialFolder {
                id: CredentialFolderId::UNSAVED,
                parent_id: fid,
                name: "New Folder".to_owned(),
                sort,
            };
            if let Err(e) = repo_ncf.upsert_credential_folder(&folder) {
                tracing::warn!("create folder failed: {e}");
                return;
            }
            let mut st = state.borrow_mut();
            if let Err(e) = st.keys_panel.reload(repo_ncf.as_ref()) {
                tracing::warn!("reload after folder create failed: {e}");
            }
            refresh_cred_model(&st, &cred_model);
        }
    });
}

fn wire_edit_cred(ctx: &Ctx) {
    ctx.ui.on_edit_cred({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |cred_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let Some(cred) = st
                .keys_panel
                .credentials()
                .iter()
                .find(|c| c.id.get() == cred_id as i64)
            else {
                return;
            };
            let kind = match cred.kind {
                CredentialKind::Password => 0,
                CredentialKind::SshKey => 1,
                CredentialKind::SshKeyWithPassphrase => 2,
            };
            let raw_folder_id = cred.folder_id.map(|f| f.get() as i32).unwrap_or(0);
            // Resolve the credential's current folder to a combo-box index so
            // the picker shows the correct folder when the editor opens.
            let selected_folder_idx = folder_name_idx(cred.folder_id, st.keys_panel.folders());
            let form = CredFormData {
                id: cred_id,
                name: SharedString::from(cred.name.as_str()),
                kind,
                username: SharedString::from(cred.username.as_deref().unwrap_or("")),
                folder_id: raw_folder_id,
                selected_folder_idx,
                secret: SharedString::from(""),
                passphrase: SharedString::from(""),
            };
            drop(st);
            ui.set_cred_form(form);
            ui.set_cred_editor_open(true);
        }
    });
}

fn wire_delete_cred_row(ctx: &Ctx) {
    ctx.ui.on_delete_cred_row({
        let state = ctx.state.clone();
        let cred_model = ctx.cred_model.clone();
        let repo_del = ctx.repo.clone();
        let weak = ctx.ui.as_weak();
        move |id, is_folder| {
            let mut st = state.borrow_mut();
            let result = if is_folder {
                repo_del.delete_credential_folder(CredentialFolderId::new(id as i64))
            } else {
                repo_del.delete_credential(CredentialId::new(id as i64))
            };
            if let Err(e) = result {
                tracing::warn!("delete cred/folder failed: {e}");
                return;
            }
            if let Err(e) = st.keys_panel.reload(repo_del.as_ref()) {
                tracing::warn!("reload after cred delete failed: {e}");
            }
            refresh_cred_model(&st, &cred_model);
            let Some(ui) = weak.upgrade() else { return };
            refresh_cred_name_list(&st, &ui);
        }
    });
}

fn wire_cred_save(ctx: &Ctx) {
    ctx.ui.on_cred_save({
        let state = ctx.state.clone();
        let cred_model = ctx.cred_model.clone();
        let repo_cs = ctx.repo.clone();
        let secrets_cs = ctx.secrets.clone();
        let toast_model = ctx.toast_model.clone();
        let toast_next_id = ctx.toast_next_id.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let mut form = ui.get_cred_form();
            // Resolve folder from the combo index (selected-folder-idx) so that
            // a move-between-folders edit is honoured, not the stale raw folder_id.
            let fid = {
                let st = state.borrow();
                folder_id_from_name_idx(form.selected_folder_idx, st.keys_panel.folders())
            };
            let kind = match form.kind {
                1 => CredentialKind::SshKey,
                2 => CredentialKind::SshKeyWithPassphrase,
                _ => CredentialKind::Password,
            };
            let cred = Credential {
                id: CredentialId::new(form.id as i64),
                name: form.name.to_string(),
                kind,
                folder_id: fid,
                username: {
                    let u = form.username.trim().to_owned();
                    if u.is_empty() { None } else { Some(u) }
                },
            };
            let upserted_id = match repo_cs.upsert_credential(&cred) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!("upsert credential failed: {e}");
                    form.secret = SharedString::from("");
                    form.passphrase = SharedString::from("");
                    ui.set_cred_form(form);
                    return;
                }
            };
            // Capture secrets before clearing them.
            let secret_text = form.secret.to_string();
            let passphrase_text = form.passphrase.to_string();
            // SECURITY: clear transient secret fields before any further ops.
            form.secret = SharedString::from("");
            form.passphrase = SharedString::from("");
            ui.set_cred_form(form);

            if !secret_text.is_empty() {
                let purpose = match kind {
                    CredentialKind::Password => CredentialPurpose::Password,
                    _ => CredentialPurpose::SshKey,
                };
                let key_ref = CredentialRef::new(upserted_id, purpose);
                if let Err(e) = secrets_cs.store(&key_ref, &Secret::from_string(secret_text)) {
                    tracing::warn!("keychain store failed: {e}");
                    push_error_toast(
                        &toast_model,
                        &toast_next_id,
                        format!("Could not save credential secret: {e}"),
                    );
                    return;
                }
            }
            if kind == CredentialKind::SshKeyWithPassphrase && !passphrase_text.is_empty() {
                let pp_ref = CredentialRef::new(upserted_id, CredentialPurpose::SshPassphrase);
                if let Err(e) = secrets_cs.store(&pp_ref, &Secret::from_string(passphrase_text)) {
                    tracing::warn!("keychain passphrase store failed: {e}");
                    push_error_toast(
                        &toast_model,
                        &toast_next_id,
                        format!("Could not save credential passphrase: {e}"),
                    );
                    return;
                }
            }

            ui.set_cred_editor_open(false);
            let mut st = state.borrow_mut();
            if let Err(e) = st.keys_panel.reload(repo_cs.as_ref()) {
                tracing::warn!("reload after cred save failed: {e}");
            }
            refresh_cred_model(&st, &cred_model);
            refresh_cred_name_list(&st, &ui);
        }
    });
}

/// P9.5 #6: how many connections directly reference credential `cred_id` as
/// their `CredentialSource::Object` -- NOT counting connections that only
/// reach it by inheriting a group's `default_credential` (that's the
/// "Inheriting:" concept the profile editor already shows separately).
/// Pure/testable; `refresh_cred_model` is the only caller.
pub(super) fn credential_usage_counts(
    connections: &[cm_core::Connection],
) -> std::collections::HashMap<i64, usize> {
    let mut counts = std::collections::HashMap::new();
    for conn in connections {
        if let Some(id) = super::tree_ctl::object_credential_id(&conn.credential_source) {
            *counts.entry(id.get()).or_insert(0) += 1;
        }
    }
    counts
}

/// The Keys-panel row badge text for a usage count -- `""` hides the badge
/// entirely (see `CredRow::used-by-label`'s doc comment, app.slint).
pub(super) fn used_by_label(count: usize) -> String {
    match count {
        0 => String::new(),
        1 => "Used by 1 connection".to_owned(),
        n => format!("Used by {n} connections"),
    }
}

pub(super) fn refresh_cred_model(state: &State, cred_model: &Rc<VecModel<CredRow>>) {
    let mut flat = state.keys_panel.flat_filtered(&state.cred_filter);
    let usage = credential_usage_counts(state.conn_tree.connections());
    for row in flat.iter_mut() {
        if !row.is_folder {
            let count = usage.get(&(row.id as i64)).copied().unwrap_or(0);
            row.used_by_label = SharedString::from(used_by_label(count).as_str());
        }
    }
    while cred_model.row_count() > 0 {
        cred_model.remove(0);
    }
    for row in flat {
        cred_model.push(row);
    }
}

pub(super) fn refresh_cred_name_list(state: &State, ui: &AppWindow) {
    let list = build_cred_name_list(
        state.keys_panel.credentials(),
        state.keys_panel.folders(),
        "Inherit from group",
    );
    let model: Rc<VecModel<SharedString>> = Rc::new(VecModel::from(list));
    ui.set_cred_name_list(ModelRc::from(model));

    let folder_list = KeysPanel::build_folder_name_list(state.keys_panel.folders());
    let fm: Rc<VecModel<SharedString>> = Rc::new(VecModel::from(folder_list));
    ui.set_folder_name_list(ModelRc::from(fm));
}

/// Map a 1-based dropdown index back to the corresponding [`CredentialFolderId`].
///
/// Index 0 (the "Root" sentinel) returns `None`.  An out-of-bounds index also
/// returns `None` (safe degradation to root).
pub(super) fn folder_id_from_name_idx(
    idx: i32,
    folders: &[CredentialFolder],
) -> Option<CredentialFolderId> {
    if idx <= 0 {
        return None;
    }
    let mut sorted: Vec<&CredentialFolder> = folders.iter().collect();
    sorted.sort_by_key(|f| (f.sort, f.id.get()));
    sorted.get((idx - 1) as usize).map(|f| f.id)
}

/// Find the 1-based dropdown index for a given [`CredentialFolderId`] in the name list.
///
/// Returns 0 (the "Root" sentinel) when `folder_id` is `None` or not found.
pub(super) fn folder_name_idx(
    folder_id: Option<CredentialFolderId>,
    folders: &[CredentialFolder],
) -> i32 {
    let Some(fid) = folder_id else { return 0 };
    let mut sorted: Vec<&CredentialFolder> = folders.iter().collect();
    sorted.sort_by_key(|f| (f.sort, f.id.get()));
    sorted
        .iter()
        .position(|f| f.id == fid)
        .map(|i| i as i32 + 1)
        .unwrap_or(0)
}

pub(super) fn resolve_cred_from_idx(
    idx: i32,
    credentials: &[Credential],
    folders: &[CredentialFolder],
) -> Option<CredentialId> {
    if idx <= 0 {
        return None;
    }
    // Build the same ordered credential sequence that build_cred_name_list
    // produces and index directly by position (idx-1, because index 0 is the
    // "Inherit" sentinel).  This avoids the name-collision bug that arose from
    // splitting on '/' and doing a first-match lookup.
    let mut ordered: Vec<CredentialId> = Vec::new();
    // Root credentials first (no folder), sorted by name.
    let mut root_creds: Vec<&Credential> = credentials
        .iter()
        .filter(|c| c.folder_id.is_none())
        .collect();
    root_creds.sort_by_key(|c| c.name.as_str());
    for c in root_creds {
        ordered.push(c.id);
    }
    // Credentials in each folder, in the same folder iteration order and name-sorted.
    for folder in folders {
        let mut folder_creds: Vec<&Credential> = credentials
            .iter()
            .filter(|c| c.folder_id == Some(folder.id))
            .collect();
        folder_creds.sort_by_key(|c| c.name.as_str());
        for c in folder_creds {
            ordered.push(c.id);
        }
    }
    ordered.get((idx - 1) as usize).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- resolve_cred_from_idx -------------------------------------------------

    fn make_cred(id: i64, folder_id: Option<i64>, name: &str) -> Credential {
        use cm_core::{CredentialFolderId, CredentialId, CredentialKind};
        Credential {
            id: CredentialId::new(id),
            name: name.to_owned(),
            kind: CredentialKind::Password,
            folder_id: folder_id.map(CredentialFolderId::new),
            username: None,
        }
    }

    fn make_folder(id: i64, name: &str) -> CredentialFolder {
        use cm_core::CredentialFolderId;
        CredentialFolder {
            id: CredentialFolderId::new(id),
            parent_id: None,
            name: name.to_owned(),
            sort: 0,
        }
    }

    #[test]
    fn resolve_cred_idx_zero_returns_none() {
        let creds = vec![make_cred(1, None, "alpha")];
        assert!(resolve_cred_from_idx(0, &creds, &[]).is_none());
    }

    #[test]
    fn resolve_cred_idx_negative_returns_none() {
        let creds = vec![make_cred(1, None, "alpha")];
        assert!(resolve_cred_from_idx(-1, &creds, &[]).is_none());
    }

    #[test]
    fn resolve_cred_idx_position_based_not_name_match() {
        // Two creds with the same bare name but in different folders.
        // Idx 1 = root "ops" (alphabetically first among root creds).
        // Idx 2 = "folder/ops" (would be a false match under old name-split logic).
        let creds = vec![make_cred(10, None, "ops"), make_cred(20, Some(99), "ops")];
        let folders = vec![make_folder(99, "folder")];
        let id1 = resolve_cred_from_idx(1, &creds, &folders);
        let id2 = resolve_cred_from_idx(2, &creds, &folders);
        use cm_core::CredentialId;
        assert_eq!(
            id1,
            Some(CredentialId::new(10)),
            "idx 1 must be root ops (id 10)"
        );
        assert_eq!(
            id2,
            Some(CredentialId::new(20)),
            "idx 2 must be folder ops (id 20)"
        );
        // Old name-split logic would return id 10 for both (first-match on "ops").
        assert_ne!(id1, id2, "position-based lookup must distinguish them");
    }

    #[test]
    fn resolve_cred_idx_out_of_bounds_returns_none() {
        let creds = vec![make_cred(1, None, "only")];
        assert!(resolve_cred_from_idx(99, &creds, &[]).is_none());
    }

    // -- folder name-list helpers ----------------------------------------------

    fn make_folder_sorted(id: i64, sort: i64, name: &str) -> CredentialFolder {
        CredentialFolder {
            id: CredentialFolderId::new(id),
            parent_id: None,
            name: name.to_owned(),
            sort,
        }
    }

    #[test]
    fn folder_id_from_name_idx_zero_is_root() {
        let folders = vec![make_folder_sorted(1, 0, "Work")];
        assert!(folder_id_from_name_idx(0, &folders).is_none());
    }

    #[test]
    fn folder_id_from_name_idx_one_is_first_sorted_folder() {
        let folders = vec![make_folder_sorted(7, 0, "Z"), make_folder_sorted(1, 0, "A")];
        // sorted: A(id=1,sort=0) then Z(id=7,sort=0) -> index 1 -> id 1
        let id = folder_id_from_name_idx(1, &folders).expect("should resolve");
        assert_eq!(id, CredentialFolderId::new(1));
    }

    #[test]
    fn folder_name_idx_round_trips() {
        let folders = vec![
            make_folder_sorted(5, 0, "Five"),
            make_folder_sorted(2, 0, "Two"),
        ];
        // sorted by (sort=0, id): Two(id=2)->1, Five(id=5)->2
        let idx_two = folder_name_idx(Some(CredentialFolderId::new(2)), &folders);
        let idx_five = folder_name_idx(Some(CredentialFolderId::new(5)), &folders);
        assert_eq!(idx_two, 1);
        assert_eq!(idx_five, 2);
        let recovered = folder_id_from_name_idx(idx_two, &folders).expect("should resolve");
        assert_eq!(recovered, CredentialFolderId::new(2));
    }

    #[test]
    fn folder_name_idx_none_returns_zero() {
        let folders = vec![make_folder_sorted(1, 0, "F")];
        assert_eq!(folder_name_idx(None, &folders), 0);
    }

    // -- credential_usage_counts / used_by_label (P9.5 #6) --------------------

    fn make_conn_with_source(
        id: i64,
        source: Option<cm_core::CredentialSource>,
    ) -> cm_core::Connection {
        use cm_core::{
            ConnectionId, ConnectionKind, ConnectionSettings, SshAuthMethod, SshSettings,
        };
        cm_core::Connection::new(
            ConnectionId::new(id),
            None,
            "c".to_owned(),
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(SshSettings {
                host: "h".to_owned(),
                port: 22,
                username: String::new(),
                auth_method: SshAuthMethod::Agent,
            }),
            source,
            0,
            0,
            0,
        )
        .unwrap()
    }

    #[test]
    fn credential_usage_counts_counts_only_direct_object_references() {
        use cm_core::{CredentialId, CredentialSource};
        let conns = vec![
            make_conn_with_source(1, Some(CredentialSource::Object(CredentialId::new(9)))),
            make_conn_with_source(2, Some(CredentialSource::Object(CredentialId::new(9)))),
            make_conn_with_source(3, Some(CredentialSource::Object(CredentialId::new(4)))),
            // Inherited (None) and Inline/Prompt never count toward an
            // OBJECT's direct usage, however they resolve.
            make_conn_with_source(5, None),
            make_conn_with_source(
                6,
                Some(CredentialSource::Inline {
                    username: "u".to_owned(),
                    domain: None,
                    has_secret: false,
                }),
            ),
            make_conn_with_source(7, Some(CredentialSource::Prompt)),
        ];
        let counts = credential_usage_counts(&conns);
        assert_eq!(counts.get(&9), Some(&2));
        assert_eq!(counts.get(&4), Some(&1));
        assert_eq!(counts.get(&99), None);
    }

    #[test]
    fn used_by_label_pluralizes_and_hides_zero() {
        assert_eq!(used_by_label(0), "");
        assert_eq!(used_by_label(1), "Used by 1 connection");
        assert_eq!(used_by_label(3), "Used by 3 connections");
    }
}
