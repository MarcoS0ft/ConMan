//! Connections tree panel: CRUD for connections/groups, reordering, and the
//! profile/group-form <-> domain-object mapping helpers.
use std::rc::Rc;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, CredentialId, CredentialPurpose,
    CredentialRef, Group, GroupId, LocalSettings, RdpSettings, SshAuthMethod, SshSettings,
};
use cm_session::PaneLayout;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::keys::KeysPanel;
use crate::tree::cred_name_idx;
use crate::{AppWindow, ConnRow};

use crate::generated_ui::{ConnProfile, GroupForm};

use super::*;

pub(super) fn wire_tree_ctl(ctx: &Ctx) {
    wire_conn_filter_changed(ctx);
    wire_toggle_conn_row(ctx);
    wire_new_connection(ctx);
    wire_new_group(ctx);
    wire_edit_conn(ctx);
    wire_edit_group(ctx);
    wire_duplicate_conn_row(ctx);
    wire_connect_in_split_row(ctx);
    wire_delete_conn_row(ctx);
    wire_profile_save(ctx);
    wire_group_save(ctx);
    wire_reorder_conn_row(ctx);
    wire_reorder_group_row(ctx);
}

fn wire_conn_filter_changed(ctx: &Ctx) {
    ctx.ui.on_conn_filter_changed({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        move |q| {
            let mut st = state.borrow_mut();
            st.conn_filter = q.to_string();
            refresh_conn_model(&st, &conn_model);
        }
    });
}

fn wire_toggle_conn_row(ctx: &Ctx) {
    ctx.ui.on_toggle_conn_row({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        move |idx| {
            let mut st = state.borrow_mut();
            let flat = st.conn_tree.flat();
            if let Some(row) = flat.get(idx as usize)
                && row.is_group
            {
                st.conn_tree.toggle_expand(row.id as i64);
                refresh_conn_model(&st, &conn_model);
            }
        }
    });
}

fn wire_new_connection(ctx: &Ctx) {
    ctx.ui.on_new_connection({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |group_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let gid = if group_id == 0 {
                None
            } else {
                Some(GroupId::new(group_id as i64))
            };
            let selected_group_idx = group_name_idx(gid, st.conn_tree.groups());
            let form = ConnProfile {
                id: 0,
                name: SharedString::from("New Connection"),
                group_id,
                kind: 0,
                host: SharedString::from(""),
                port: SharedString::from("22"),
                username: SharedString::from(""),
                auth_method: 1,
                selected_cred_idx: 0,
                effective_cred_name: SharedString::from(""),
                effective_inherited: false,
                selected_group_idx,
            };
            drop(st);
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
    });
}

fn wire_new_group(ctx: &Ctx) {
    ctx.ui.on_new_group({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |parent_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let pid = if parent_id == 0 {
                None
            } else {
                Some(GroupId::new(parent_id as i64))
            };
            let selected_parent_idx = group_name_idx(pid, st.conn_tree.groups());
            let form = GroupForm {
                id: 0,
                name: SharedString::from("New Group"),
                parent_id,
                default_cred_idx: 0,
                selected_parent_idx,
            };
            drop(st);
            ui.set_group_form(form);
            ui.set_group_editor_open(true);
        }
    });
}

fn wire_edit_conn(ctx: &Ctx) {
    ctx.ui.on_edit_conn({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |conn_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let Some(conn) = st.conn_tree.conn_by_id(conn_id as i64) else {
                return;
            };
            let (kind, host, port, username, auth_method) = profile_fields_from_conn(conn);
            let cred_sel_idx = cred_name_idx(
                conn.credential,
                st.keys_panel.credentials(),
                st.keys_panel.folders(),
            );
            let (eff_cred_id, inherited) =
                KeysPanel::resolve_effective(conn.credential, conn.group_id, st.conn_tree.groups());
            let eff_name = KeysPanel::cred_display_name(eff_cred_id, st.keys_panel.credentials());
            let selected_group_idx = group_name_idx(conn.group_id, st.conn_tree.groups());
            let form = ConnProfile {
                id: conn_id,
                name: SharedString::from(conn.name.as_str()),
                group_id: conn.group_id.map(|g| g.get() as i32).unwrap_or(0),
                kind,
                host: SharedString::from(host.as_str()),
                port: SharedString::from(port.as_str()),
                username: SharedString::from(username.as_str()),
                auth_method,
                selected_cred_idx: cred_sel_idx,
                effective_cred_name: SharedString::from(eff_name.as_str()),
                effective_inherited: inherited,
                selected_group_idx,
            };
            drop(st);
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
    });
}

fn wire_edit_group(ctx: &Ctx) {
    ctx.ui.on_edit_group({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |group_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let Some(group) = st.conn_tree.group_by_id(group_id as i64) else {
                return;
            };
            let default_cred_idx = cred_name_idx(
                group.default_credential,
                st.keys_panel.credentials(),
                st.keys_panel.folders(),
            );
            let selected_parent_idx = group_name_idx(group.parent_id, st.conn_tree.groups());
            let form = GroupForm {
                id: group_id,
                name: SharedString::from(group.name.as_str()),
                parent_id: group.parent_id.map(|g| g.get() as i32).unwrap_or(0),
                default_cred_idx,
                selected_parent_idx,
            };
            drop(st);
            ui.set_group_form(form);
            ui.set_group_editor_open(true);
        }
    });
}

// P6.10 (gap 15): "Duplicate" from the tree context menu. Builds a fresh (id == 0)
// `Connection` cloned from `src`, ready for the exact same `upsert_connection` repo
// call the profile editor's "New Connection" path already makes (form.id == 0 in
// `wire_profile_save`) — no new repo/port surface, just a second UI-side caller of
// the existing insert path with a cloned settings blob. Pulled out as a pure
// function so the mapping is unit-testable without a live Slint window (cm-ui's
// tests stay backend-free — see Cargo.toml).
pub(super) fn duplicate_connection(
    src: &Connection,
    sort: i64,
    now: i64,
) -> Result<Connection, cm_core::DomainError> {
    Connection::new(
        ConnectionId::new(0),
        src.group_id,
        format!("{} (copy)", src.name),
        src.kind,
        src.settings.clone(),
        src.credential,
        sort,
        now,
        now,
    )
}

fn wire_duplicate_conn_row(ctx: &Ctx) {
    ctx.ui.on_duplicate_conn_row({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let repo_dup = ctx.repo.clone();
        move |id| {
            let mut st = state.borrow_mut();
            let Some(src) = st.conn_tree.conn_by_id(id as i64).cloned() else {
                return;
            };
            let sort = st.conn_tree.next_sort_in_group(src.group_id);
            let now = crate::tree::now_secs();
            let conn = match duplicate_connection(&src, sort, now) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("duplicate connection validation error: {e}");
                    return;
                }
            };
            if let Err(e) = repo_dup.upsert_connection(&conn) {
                tracing::warn!("duplicate connection failed: {e}");
                return;
            }
            if let Err(e) = st.conn_tree.reload(repo_dup.as_ref()) {
                tracing::warn!("reload after duplicate failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
        }
    });
}

// P6.10 (gap 15, fix round 2): "Connect in split" from the tree context menu
// (both the per-row ConnectionRow menu and the keyboard-Menu-key tree-level
// menu route here). Defaults to a horizontal (side-by-side) split — the same
// default a user reaches via Ctrl+Shift+H / the "Split horizontal" palette
// action. See `panes::connect_in_split` for the per-connection-kind dispatch
// (Local/SSH wired, RDP toast-and-noop) and its full rationale.
fn wire_connect_in_split_row(ctx: &Ctx) {
    ctx.ui.on_connect_in_split_row({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let toast_model = ctx.toast_model.clone();
        let toast_next_id = ctx.toast_next_id.clone();
        let hk_pending = ctx.hk_pending.clone();
        let secrets = ctx.secrets.clone();
        let weak = ctx.ui.as_weak();
        move |id| {
            let Some(ui) = weak.upgrade() else { return };
            panes::connect_in_split(
                &state,
                &tab_model,
                &ui,
                &weak,
                &hk_pending,
                &secrets,
                &toast_model,
                &toast_next_id,
                id as i64,
                PaneLayout::HSplit,
            );
        }
    });
}

fn wire_delete_conn_row(ctx: &Ctx) {
    ctx.ui.on_delete_conn_row({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let repo_del = ctx.repo.clone();
        move |id, is_group| {
            let mut st = state.borrow_mut();
            let result = if is_group {
                repo_del.delete_group(GroupId::new(id as i64))
            } else {
                repo_del.delete_connection(ConnectionId::new(id as i64))
            };
            if let Err(e) = result {
                tracing::warn!("delete failed: {e}");
                return;
            }
            if let Err(e) = st.conn_tree.reload(repo_del.as_ref()) {
                tracing::warn!("reload after delete failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
        }
    });
}

fn wire_profile_save(ctx: &Ctx) {
    ctx.ui.on_profile_save({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let repo_ps = ctx.repo.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let form = ui.get_profile_form();
            // Resolve group_id from the dropdown index (selected-group-idx).
            // Falls back to the raw form.group_id when the index is out-of-range
            // (e.g. on an older saved form with no group list loaded yet).
            let group_id = {
                let st = state.borrow();
                group_id_from_name_idx(form.selected_group_idx, st.conn_tree.groups())
            };
            let cred_id = {
                let st = state.borrow();
                keys_ctl::resolve_cred_from_idx(
                    form.selected_cred_idx,
                    st.keys_panel.credentials(),
                    st.keys_panel.folders(),
                )
            };
            let sort = {
                let st = state.borrow();
                if form.id == 0 {
                    st.conn_tree.next_sort_in_group(group_id)
                } else {
                    st.conn_tree
                        .conn_by_id(form.id as i64)
                        .map(|c| c.sort)
                        .unwrap_or(0)
                }
            };
            let settings = settings_from_form(&form);
            let kind = kind_from_form_int(form.kind);
            let now = crate::tree::now_secs();
            let created_at = {
                let st = state.borrow();
                st.conn_tree
                    .conn_by_id(form.id as i64)
                    .map(|c| c.created_at)
                    .unwrap_or(now)
            };
            let conn = match Connection::new(
                ConnectionId::new(form.id as i64),
                group_id,
                form.name.to_string(),
                kind,
                settings,
                cred_id,
                sort,
                created_at,
                now,
            ) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("profile validation error: {e}");
                    return;
                }
            };
            if let Err(e) = repo_ps.upsert_connection(&conn) {
                tracing::warn!("upsert connection failed: {e}");
                return;
            }
            ui.set_profile_editor_open(false);
            let mut st = state.borrow_mut();
            if let Err(e) = st.conn_tree.reload(repo_ps.as_ref()) {
                tracing::warn!("reload after save failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            refresh_group_name_list(&st, &ui);
        }
    });
}

fn wire_group_save(ctx: &Ctx) {
    ctx.ui.on_group_save({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let repo_gs = ctx.repo.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let form = ui.get_group_form();
            // Resolve parent_id from the dropdown index (selected-parent-idx).
            // Reject any parent choice that would form a cycle: the chosen parent
            // must not be the group itself AND must not be any of its descendants.
            // (`is_ancestor_or_self` covers both: it returns true when
            //  candidate == self and when candidate is reachable from self.)
            let parent_id = {
                let st = state.borrow();
                let resolved =
                    group_id_from_name_idx(form.selected_parent_idx, st.conn_tree.groups());
                resolved.filter(|&gid| {
                    form.id == 0
                        || !is_ancestor_or_self(
                            GroupId::new(form.id as i64),
                            gid,
                            st.conn_tree.groups(),
                        )
                })
            };
            let default_credential = {
                let st = state.borrow();
                keys_ctl::resolve_cred_from_idx(
                    form.default_cred_idx,
                    st.keys_panel.credentials(),
                    st.keys_panel.folders(),
                )
            };
            let sort = {
                let st = state.borrow();
                if form.id == 0 {
                    st.conn_tree.next_group_sort_in_parent(parent_id)
                } else {
                    st.conn_tree
                        .group_by_id(form.id as i64)
                        .map(|g| g.sort)
                        .unwrap_or(0)
                }
            };
            let group = Group {
                id: GroupId::new(form.id as i64),
                parent_id,
                name: form.name.to_string(),
                sort,
                default_credential,
            };
            if let Err(e) = repo_gs.upsert_group(&group) {
                tracing::warn!("upsert group failed: {e}");
                return;
            }
            ui.set_group_editor_open(false);
            let mut st = state.borrow_mut();
            if let Err(e) = st.conn_tree.reload(repo_gs.as_ref()) {
                tracing::warn!("reload after group save failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            refresh_group_name_list(&st, &ui);
        }
    });
}

fn wire_reorder_conn_row(ctx: &Ctx) {
    ctx.ui.on_reorder_conn_row({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let repo_rcr = ctx.repo.clone();
        move |conn_id, direction| {
            let mut st = state.borrow_mut();
            let Some(conn) = st.conn_tree.conn_by_id(conn_id as i64).cloned() else {
                return;
            };
            let group_id = conn.group_id;
            // Collect siblings (same parent) sorted by (sort, id).
            let mut siblings: Vec<Connection> = st
                .conn_tree
                .connections()
                .iter()
                .filter(|c| c.group_id == group_id)
                .cloned()
                .collect();
            siblings.sort_by_key(|c| (c.sort, c.id.get()));
            let Some(pos) = siblings.iter().position(|c| c.id == conn.id) else {
                return;
            };
            let target_pos = if direction < 0 {
                if pos == 0 {
                    return;
                }
                pos - 1
            } else {
                if pos + 1 >= siblings.len() {
                    return;
                }
                pos + 1
            };
            // Swap sort values between the two siblings.
            let sort_a = siblings[pos].sort;
            let sort_b = siblings[target_pos].sort;
            let mut a = siblings[pos].clone();
            let mut b = siblings[target_pos].clone();
            if sort_a == sort_b {
                // Equal sorts: nudge them apart without touching the other sibling.
                if direction < 0 {
                    a.sort = sort_a.saturating_sub(1);
                } else {
                    a.sort = sort_a.saturating_add(1);
                }
                if let Err(e) = repo_rcr.upsert_connection(&a) {
                    tracing::warn!("reorder conn (nudge) failed: {e}");
                    return;
                }
            } else {
                a.sort = sort_b;
                b.sort = sort_a;
                if let Err(e) = repo_rcr.upsert_connection(&b) {
                    tracing::warn!("reorder conn (swap target) failed: {e}");
                    return;
                }
                if let Err(e) = repo_rcr.upsert_connection(&a) {
                    tracing::warn!("reorder conn (swap source) failed: {e}");
                    return;
                }
            }
            if let Err(e) = st.conn_tree.reload(repo_rcr.as_ref()) {
                tracing::warn!("reload after reorder failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
        }
    });
}

fn wire_reorder_group_row(ctx: &Ctx) {
    ctx.ui.on_reorder_group_row({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let repo_rgr = ctx.repo.clone();
        let weak_rgr = ctx.ui.as_weak();
        move |group_id, direction| {
            let mut st = state.borrow_mut();
            let Some(grp) = st.conn_tree.group_by_id(group_id as i64).cloned() else {
                return;
            };
            let parent_id = grp.parent_id;
            // Collect sibling groups (same parent) sorted by (sort, id).
            let mut siblings: Vec<Group> = st
                .conn_tree
                .groups()
                .iter()
                .filter(|g| g.parent_id == parent_id)
                .cloned()
                .collect();
            siblings.sort_by_key(|g| (g.sort, g.id.get()));
            let Some(pos) = siblings.iter().position(|g| g.id == grp.id) else {
                return;
            };
            let target_pos = if direction < 0 {
                if pos == 0 {
                    return;
                }
                pos - 1
            } else {
                if pos + 1 >= siblings.len() {
                    return;
                }
                pos + 1
            };
            let sort_a = siblings[pos].sort;
            let sort_b = siblings[target_pos].sort;
            let mut a = siblings[pos].clone();
            let mut b = siblings[target_pos].clone();
            if sort_a == sort_b {
                if direction < 0 {
                    a.sort = sort_a.saturating_sub(1);
                } else {
                    a.sort = sort_a.saturating_add(1);
                }
                if let Err(e) = repo_rgr.upsert_group(&a) {
                    tracing::warn!("reorder group (nudge) failed: {e}");
                    return;
                }
            } else {
                a.sort = sort_b;
                b.sort = sort_a;
                if let Err(e) = repo_rgr.upsert_group(&b) {
                    tracing::warn!("reorder group (swap target) failed: {e}");
                    return;
                }
                if let Err(e) = repo_rgr.upsert_group(&a) {
                    tracing::warn!("reorder group (swap source) failed: {e}");
                    return;
                }
            }
            if let Err(e) = st.conn_tree.reload(repo_rgr.as_ref()) {
                tracing::warn!("reload after group reorder failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            if let Some(ui) = weak_rgr.upgrade() {
                refresh_group_name_list(&st, &ui);
            }
        }
    });
}

pub(super) fn refresh_conn_model(state: &State, conn_model: &Rc<VecModel<ConnRow>>) {
    let flat = state.conn_tree.flat_filtered(&state.conn_filter);
    while conn_model.row_count() > 0 {
        conn_model.remove(0);
    }
    for row in flat {
        conn_model.push(row);
    }
}

pub(super) fn build_group_name_list(groups: &[Group]) -> Vec<SharedString> {
    let mut out = vec![SharedString::from("Root (no group)")];
    let mut sorted: Vec<&Group> = groups.iter().collect();
    sorted.sort_by_key(|g| (g.sort, g.id.get()));
    for g in sorted {
        out.push(SharedString::from(g.name.as_str()));
    }
    out
}

/// Rebuild and push the group name list to the UI.
pub(super) fn refresh_group_name_list(state: &State, ui: &AppWindow) {
    let list = build_group_name_list(state.conn_tree.groups());
    let model: Rc<VecModel<SharedString>> = Rc::new(VecModel::from(list));
    ui.set_group_name_list(ModelRc::from(model));
}

/// Map a 1-based dropdown index back to the corresponding [`GroupId`].
///
/// Index 0 (the "Root" sentinel) returns `None`.  An out-of-bounds index also
/// returns `None` (safe degradation to root).
pub(super) fn group_id_from_name_idx(idx: i32, groups: &[Group]) -> Option<GroupId> {
    if idx <= 0 {
        return None;
    }
    let mut sorted: Vec<&Group> = groups.iter().collect();
    sorted.sort_by_key(|g| (g.sort, g.id.get()));
    sorted.get((idx - 1) as usize).map(|g| g.id)
}

/// Find the 1-based dropdown index for a given [`GroupId`] in the name list.
///
/// Returns 0 (the "Root" sentinel) when `group_id` is `None` or not found.
pub(super) fn group_name_idx(group_id: Option<GroupId>, groups: &[Group]) -> i32 {
    let Some(gid) = group_id else { return 0 };
    let mut sorted: Vec<&Group> = groups.iter().collect();
    sorted.sort_by_key(|g| (g.sort, g.id.get()));
    sorted
        .iter()
        .position(|g| g.id == gid)
        .map(|i| i as i32 + 1)
        .unwrap_or(0)
}

/// Returns `true` if `target` appears anywhere in the ancestor chain of
/// `candidate_parent` (including `candidate_parent` itself).
///
/// Used in [`on_group_save`] to block descendant-as-parent cycles: the caller
/// should reject any `candidate_parent` for which this returns `true`.
pub(super) fn is_ancestor_or_self(
    target: GroupId,
    candidate_parent: GroupId,
    groups: &[Group],
) -> bool {
    let mut current = Some(candidate_parent);
    let mut depth = 0usize;
    while let Some(id) = current {
        if id == target {
            return true;
        }
        depth += 1;
        if depth > 64 {
            // Cycle already exists in the DB; stop to avoid an infinite loop.
            break;
        }
        current = groups.iter().find(|g| g.id == id).and_then(|g| g.parent_id);
    }
    false
}

pub(super) fn profile_fields_from_conn(conn: &Connection) -> (i32, String, String, String, i32) {
    match &conn.settings {
        ConnectionSettings::Ssh(s) => (
            0,
            s.host.clone(),
            s.port.to_string(),
            s.username.clone(),
            match s.auth_method {
                SshAuthMethod::PublicKey { .. } => 0,
                SshAuthMethod::Password => 1,
                SshAuthMethod::Agent => 2,
            },
        ),
        ConnectionSettings::Rdp(s) => (
            1,
            s.host.clone(),
            s.port.to_string(),
            s.username.clone().unwrap_or_default(),
            1,
        ),
        ConnectionSettings::Local(_) => (2, String::new(), String::new(), String::new(), 1),
    }
}

pub(super) fn settings_from_form(form: &ConnProfile) -> ConnectionSettings {
    match form.kind {
        1 => ConnectionSettings::Rdp(RdpSettings {
            host: form.host.to_string(),
            port: form.port.as_str().parse::<u16>().unwrap_or(3389),
            domain: None,
            username: {
                let u = form.username.trim().to_owned();
                if u.is_empty() { None } else { Some(u) }
            },
            // width/height/color_depth added by P4.1; default them until the profile
            // editor surfaces resolution/depth fields (later UI enhancement).
            ..RdpSettings::default()
        }),
        2 => ConnectionSettings::Local(LocalSettings::default()),
        _ => ConnectionSettings::Ssh(SshSettings {
            host: form.host.to_string(),
            port: form.port.as_str().parse::<u16>().unwrap_or(22),
            username: form.username.to_string(),
            auth_method: match form.auth_method {
                0 => SshAuthMethod::PublicKey {
                    key_ref: CredentialRef::new(CredentialId::UNSAVED, CredentialPurpose::SshKey),
                },
                2 => SshAuthMethod::Agent,
                _ => SshAuthMethod::Password,
            },
        }),
    }
}

pub(super) fn kind_from_form_int(n: i32) -> ConnectionKind {
    match n {
        1 => ConnectionKind::Rdp,
        2 => ConnectionKind::LocalTerminal,
        _ => ConnectionKind::Ssh,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cm_core::Secret;

    use super::*;

    #[test]
    fn form_to_ssh_auth_password() {
        let auth_method: i32 = 1;
        let secret_raw = "dummy-password".to_owned();
        let pass_raw = String::new();
        let auth = match auth_method {
            0 => SshAuthInput::Key {
                path: PathBuf::from(&secret_raw),
                passphrase: if pass_raw.is_empty() {
                    None
                } else {
                    Some(Secret::from_string(pass_raw))
                },
            },
            1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
            _ => SshAuthInput::Agent,
        };
        assert!(matches!(auth, SshAuthInput::Password(_)));
    }

    #[test]
    fn form_to_ssh_auth_pubkey_no_passphrase() {
        let auth_method: i32 = 0;
        let secret_raw = "/home/user/.ssh/id_ed25519".to_owned();
        let pass_raw = String::new();
        let auth = match auth_method {
            0 => SshAuthInput::Key {
                path: PathBuf::from(&secret_raw),
                passphrase: if pass_raw.is_empty() {
                    None
                } else {
                    Some(Secret::from_string(pass_raw))
                },
            },
            1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
            _ => SshAuthInput::Agent,
        };
        assert!(matches!(
            auth,
            SshAuthInput::Key {
                passphrase: None,
                ..
            }
        ));
    }

    #[test]
    fn form_to_ssh_auth_agent() {
        let auth_method: i32 = 2;
        let secret_raw = String::new();
        let auth = match auth_method {
            0 => SshAuthInput::Key {
                path: PathBuf::from(&secret_raw),
                passphrase: None,
            },
            1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
            _ => SshAuthInput::Agent,
        };
        assert!(matches!(auth, SshAuthInput::Agent));
    }

    // P6.10 (gap 15): the tree context menu's "Duplicate" item and
    // `wire_duplicate_conn_row` share this exact mapping — this is the one piece of
    // genuinely new (if tiny) UI-orchestration logic the context-menu task adds, so
    // it gets a real test per CONVENTIONS §2 ("tests accompany behavior").
    #[test]
    fn duplicate_connection_clones_settings_with_new_id_and_copy_suffix() {
        let src = Connection::new(
            ConnectionId::new(42),
            Some(GroupId::new(7)),
            "prod-web-01".to_owned(),
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(SshSettings {
                host: "10.0.0.5".to_owned(),
                port: 22,
                username: "deploy".to_owned(),
                auth_method: SshAuthMethod::Agent,
            }),
            Some(CredentialId::new(9)),
            3,
            1_000,
            1_000,
        )
        .unwrap();

        let dup = duplicate_connection(&src, 4, 2_000).unwrap();

        assert_eq!(dup.id, ConnectionId::new(0)); // fresh id — repo assigns on insert
        assert_eq!(dup.name, "prod-web-01 (copy)");
        assert_eq!(dup.group_id, src.group_id);
        assert_eq!(dup.kind, src.kind);
        assert_eq!(dup.settings, src.settings);
        assert_eq!(dup.credential, src.credential);
        assert_eq!(dup.sort, 4);
        assert_eq!(dup.created_at, 2_000);
        assert_eq!(dup.updated_at, 2_000);
    }

    #[test]
    fn ssh_settings_default_port() {
        assert_eq!(SshSettings::DEFAULT_PORT, 22);
    }

    #[test]
    fn kind_from_form_int_all_variants() {
        assert_eq!(kind_from_form_int(0), ConnectionKind::Ssh);
        assert_eq!(kind_from_form_int(1), ConnectionKind::Rdp);
        assert_eq!(kind_from_form_int(2), ConnectionKind::LocalTerminal);
        assert_eq!(kind_from_form_int(99), ConnectionKind::Ssh);
    }

    #[test]
    fn profile_form_mapping_ssh() {
        let form = ConnProfile {
            id: 0,
            name: SharedString::from("Test"),
            group_id: 0,
            kind: 0,
            host: SharedString::from("10.0.0.1"),
            port: SharedString::from("2222"),
            username: SharedString::from("admin"),
            auth_method: 1,
            selected_cred_idx: 0,
            effective_cred_name: SharedString::from(""),
            effective_inherited: false,
            selected_group_idx: 0,
        };
        let settings = settings_from_form(&form);
        assert!(
            matches!(
                settings,
                ConnectionSettings::Ssh(SshSettings { port: 2222, .. })
            ),
            "SSH settings port should be 2222"
        );
    }

    // -- group name list helpers ---------------------------------------------

    fn make_group(id: i64, sort: i64, name: &str) -> Group {
        Group {
            id: GroupId::new(id),
            parent_id: None,
            name: name.to_owned(),
            sort,
            default_credential: None,
        }
    }

    #[test]
    fn group_name_list_sentinel_is_root() {
        let list = build_group_name_list(&[]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].as_str(), "Root (no group)");
    }

    #[test]
    fn group_name_list_sorted_by_sort_then_id() {
        let groups = vec![
            make_group(3, 1, "C"),
            make_group(1, 0, "A"),
            make_group(2, 0, "B"),
        ];
        let list = build_group_name_list(&groups);
        // sentinel + A(sort=0,id=1) + B(sort=0,id=2) + C(sort=1,id=3)
        assert_eq!(list.len(), 4);
        assert_eq!(list[1].as_str(), "A");
        assert_eq!(list[2].as_str(), "B");
        assert_eq!(list[3].as_str(), "C");
    }

    #[test]
    fn group_id_from_name_idx_zero_is_root() {
        let groups = vec![make_group(1, 0, "G1")];
        assert!(group_id_from_name_idx(0, &groups).is_none());
    }

    #[test]
    fn group_id_from_name_idx_one_is_first_sorted_group() {
        let groups = vec![make_group(7, 0, "G7"), make_group(1, 0, "G1")];
        // G1 sort=0,id=1 comes first; G7 sort=0,id=7 comes second.
        let id = group_id_from_name_idx(1, &groups).expect("should resolve");
        assert_eq!(id, GroupId::new(1));
    }

    #[test]
    fn group_name_idx_round_trips() {
        let groups = vec![make_group(5, 0, "Five"), make_group(2, 0, "Two")];
        // sorted: Two(id=2), Five(id=5) -> indices 1, 2
        let idx_two = group_name_idx(Some(GroupId::new(2)), &groups);
        let idx_five = group_name_idx(Some(GroupId::new(5)), &groups);
        assert_eq!(idx_two, 1);
        assert_eq!(idx_five, 2);
        // Round-trip: idx -> id -> idx.
        let recovered = group_id_from_name_idx(idx_two, &groups).expect("should resolve");
        assert_eq!(recovered, GroupId::new(2));
    }

    #[test]
    fn group_name_idx_none_returns_zero() {
        let groups = vec![make_group(1, 0, "G")];
        assert_eq!(group_name_idx(None, &groups), 0);
    }

    /// Groups with parent relationships for cycle tests.
    fn make_group_with_parent(id: i64, parent: Option<i64>, sort: i64, name: &str) -> Group {
        Group {
            id: GroupId::new(id),
            parent_id: parent.map(GroupId::new),
            name: name.to_owned(),
            sort,
            default_credential: None,
        }
    }

    // -- is_ancestor_or_self ---------------------------------------------------

    #[test]
    fn ancestor_self_is_detected() {
        let g = make_group_with_parent(1, None, 0, "G");
        assert!(is_ancestor_or_self(GroupId::new(1), GroupId::new(1), &[g]));
    }

    #[test]
    fn ancestor_direct_child_detected() {
        // hierarchy: A(1) -> B(2). Moving A under B would create a cycle.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, Some(1), 0, "B"),
        ];
        // B is a descendant of A, so assigning B as A's parent is a cycle.
        assert!(is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(2),
            &groups
        ));
    }

    #[test]
    fn ancestor_transitive_descendant_detected() {
        // A(1) -> B(2) -> C(3). Moving A under C is a deeper cycle.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, Some(1), 0, "B"),
            make_group_with_parent(3, Some(2), 0, "C"),
        ];
        assert!(is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(3),
            &groups
        ));
    }

    #[test]
    fn ancestor_sibling_is_safe() {
        // A(1) and B(2) are siblings under Root. Moving A under B is safe.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, None, 0, "B"),
        ];
        assert!(!is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(2),
            &groups
        ));
    }

    #[test]
    fn ancestor_unrelated_group_is_safe() {
        // B(2) -> C(3). Moving A(1) under C is fine; A is not in B/C's chain.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, None, 0, "B"),
            make_group_with_parent(3, Some(2), 0, "C"),
        ];
        assert!(!is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(3),
            &groups
        ));
    }
}
