//! Connections tree panel: CRUD for connections/groups, reordering, and the
//! profile/group-form <-> domain-object mapping helpers.
use std::rc::Rc;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, CredentialId, CredentialPurpose,
    CredentialRef, CredentialSource, Group, GroupId, LocalSettings, RdpSettings, Secret,
    SshAuthMethod, SshSettings,
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
    wire_select_conn_row(ctx);
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

/// P9.5 #2: a single click on a leaf connection row selects/highlights it
/// (`ConnRow.selected`) rather than launching -- launching now needs a
/// double click (`wire_row_activated`, sessions.rs) or keyboard Enter
/// (wired directly to `row-activated` at the AppWindow level, unchanged).
/// Mirrors [`wire_toggle_conn_row`]'s idx -> flat-row -> mutate-tree ->
/// refresh-model shape; groups are ignored here (their single click still
/// toggles expand/collapse via `wire_toggle_conn_row`, unaffected).
fn wire_select_conn_row(ctx: &Ctx) {
    ctx.ui.on_row_selected({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        move |idx| {
            let mut st = state.borrow_mut();
            let flat = st.conn_tree.flat();
            if let Some(row) = flat.get(idx as usize)
                && !row.is_group
            {
                st.conn_tree.select_conn(row.id as i64);
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
                effective_cred_username: SharedString::from(""),
                effective_inherited: false,
                selected_group_idx,
                rdp_domain: SharedString::from(""),
                rdp_resolution: SharedString::from(default_rdp_resolution().as_str()),
                // P9.6-A Phase C: a new connection starts in Reference mode
                // (index 0 = "Inherit from group"), matching pre-P9.6 default
                // behavior exactly.
                cred_mode: 0,
                inline_password: SharedString::from(""),
                inline_has_secret: false,
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

/// P9.6-A mechanical fix: the credential-object id a connection points at
/// directly (not counting group inheritance) -- what `Connection::credential:
/// Option<CredentialId>` used to BE before it became `credential_source:
/// Option<CredentialSource>`. `None` for every other source (inherit/Inline/
/// Prompt), matching that field's old meaning exactly. Still what the
/// Reference-mode dropdown itself resolves (`cred_name_idx`/
/// `KeysPanel::resolve_effective`, `resolve_cred_from_idx`) -- Inline/Prompt
/// modes are handled alongside it via `cred_mode_fields`/
/// `credential_source_from_form`, not by extending this helper's contract.
pub(super) fn object_credential_id(source: &Option<CredentialSource>) -> Option<CredentialId> {
    match source {
        Some(CredentialSource::Object(id)) => Some(*id),
        _ => None,
    }
}

/// P9.6-A Phase C: derives the mode-selector's `cred-mode` (0=Reference,
/// 1=Inline, 2=Prompt) plus the Inline-only username/domain overrides.
/// `Inline`'s own `username`/`domain` are the model's authoritative source
/// for those fields (`resolve_connection_auth`'s Decision 3) -- NOT
/// `conn.settings`, which `profile_fields_from_conn` already derived and
/// which the caller overrides with these `Some(_)` values only when Inline.
/// `has_secret` mirrors the enum's own flag; false for every other source.
pub(super) fn cred_mode_fields(
    source: &Option<CredentialSource>,
) -> (i32, Option<String>, Option<String>, bool) {
    match source {
        Some(CredentialSource::Inline {
            username,
            domain,
            has_secret,
        }) => (1, Some(username.clone()), domain.clone(), *has_secret),
        Some(CredentialSource::Prompt) => (2, None, None, false),
        _ => (0, None, None, false),
    }
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
            let (kind, host, port, mut username, auth_method, mut rdp_domain, rdp_resolution) =
                profile_fields_from_conn(conn);
            let (cred_mode, inline_username, inline_domain, inline_has_secret) =
                cred_mode_fields(&conn.credential_source);
            if let Some(u) = inline_username {
                username = u;
            }
            if let Some(d) = inline_domain {
                rdp_domain = d;
            }
            let cred_sel_idx = cred_name_idx(
                object_credential_id(&conn.credential_source),
                st.keys_panel.credentials(),
                st.keys_panel.folders(),
            );
            let (eff_cred_id, inherited) = KeysPanel::resolve_effective(
                object_credential_id(&conn.credential_source),
                conn.group_id,
                st.conn_tree.groups(),
            );
            let eff_name = KeysPanel::cred_display_name(eff_cred_id, st.keys_panel.credentials());
            // P9.5 #6: the bound credential's own username, shown read-only
            // next to its name (Reference mode only -- see `cred-mode == 0`
            // in profile_editor.slint).
            let eff_username = eff_cred_id
                .and_then(|id| st.keys_panel.credentials().iter().find(|c| c.id == id))
                .and_then(|c| c.username.clone())
                .unwrap_or_default();
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
                effective_cred_username: SharedString::from(eff_username.as_str()),
                effective_inherited: inherited,
                selected_group_idx,
                rdp_domain: SharedString::from(rdp_domain.as_str()),
                rdp_resolution: SharedString::from(rdp_resolution.as_str()),
                cred_mode,
                // Never populate the actual secret -- only its presence.
                inline_password: SharedString::from(""),
                inline_has_secret,
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
    // P9.6-A: copy the credential source as-is for Object/Prompt/inherit --
    // unaffected by the new connection getting a fresh id. Inline is the one
    // exception: its secret lives in the keychain keyed to `src`'s OWN
    // connection id (`CredentialRef::for_connection`), which this pure
    // mapping function has no store handle to copy -- so the duplicate keeps
    // the inline username/domain but reports `has_secret: false` here.
    // `wire_duplicate_conn_row` (this file) is the caller that DOES have a
    // store handle: it copies the actual secret and persists the corrected
    // flag via `copy_inline_secret_on_duplicate` immediately after inserting
    // the row this function returns.
    let credential_source = match &src.credential_source {
        Some(CredentialSource::Inline {
            username, domain, ..
        }) => Some(CredentialSource::Inline {
            username: username.clone(),
            domain: domain.clone(),
            has_secret: false,
        }),
        other => other.clone(),
    };
    Connection::new(
        ConnectionId::new(0),
        src.group_id,
        format!("{} (copy)", src.name),
        src.kind,
        src.settings.clone(),
        credential_source,
        sort,
        now,
        now,
    )
}

/// Follow-up to `duplicate_connection`'s deliberate `has_secret: false`
/// (that pure mapping function has no store handle to copy the source's
/// keychain secret -- see its doc comment): copies `conn:<src_id>:password`
/// to `conn:<new_id>:password`, then persists the corrected `has_secret`
/// flag. Best-effort and non-fatal -- `conn` (already inserted by the
/// caller) stays exactly as `duplicate_connection` left it on any failure
/// here: a working duplicate whose password just needs to be re-entered,
/// not a broken one. Only called when `src`'s source was Inline with a
/// secret to begin with.
fn copy_inline_secret_on_duplicate(
    repo: &dyn cm_core::ConnectionRepository,
    secrets: &dyn cm_core::CredentialStore,
    conn: &Connection,
    src_id: ConnectionId,
    new_id: ConnectionId,
) {
    let secret = match secrets.get(&CredentialRef::for_connection(
        src_id,
        CredentialPurpose::Password,
    )) {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!("duplicate: reading source Inline secret failed: {e}");
            return;
        }
    };
    let new_ref = CredentialRef::for_connection(new_id, CredentialPurpose::Password);
    if let Err(e) = secrets.store(&new_ref, &secret) {
        tracing::warn!("duplicate: storing copied Inline secret failed: {e}");
        return;
    }
    let Some(CredentialSource::Inline {
        username, domain, ..
    }) = &conn.credential_source
    else {
        return; // unreachable given the caller's guard, but stay defensive.
    };
    let mut updated = conn.clone();
    updated.id = new_id;
    updated.credential_source = Some(CredentialSource::Inline {
        username: username.clone(),
        domain: domain.clone(),
        has_secret: true,
    });
    if let Err(e) = repo.upsert_connection(&updated) {
        tracing::warn!("duplicate: persisting has_secret flag failed: {e}");
    }
}

fn wire_duplicate_conn_row(ctx: &Ctx) {
    ctx.ui.on_duplicate_conn_row({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let cred_model = ctx.cred_model.clone();
        let repo_dup = ctx.repo.clone();
        let secrets_dup = ctx.secrets.clone();
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
            let new_id = match repo_dup.upsert_connection(&conn) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!("duplicate connection failed: {e}");
                    return;
                }
            };
            if let Some(CredentialSource::Inline {
                has_secret: true, ..
            }) = &src.credential_source
            {
                copy_inline_secret_on_duplicate(
                    repo_dup.as_ref(),
                    secrets_dup.as_ref(),
                    &conn,
                    src.id,
                    new_id,
                );
            }
            if let Err(e) = st.conn_tree.reload(repo_dup.as_ref()) {
                tracing::warn!("reload after duplicate failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            // P9.5 #6: a duplicated Object-credentialed connection bumps that
            // credential's "used by N connections" badge.
            keys_ctl::refresh_cred_model(&st, &cred_model);
        }
    });
}

// P6.10 (gap 15, fix round 2)/P6.11: "Connect in split" from the tree context
// menu (both the per-row ConnectionRow menu and the keyboard-Menu-key
// tree-level menu route here). Defaults to a horizontal (side-by-side) split
// — the same default a user reaches via Ctrl+Shift+\ / the "Split
// horizontal" palette action. See `panes::connect_in_split` for the
// per-connection-kind dispatch — Local/SSH/RDP all wired since P6.11 lifted
// the RDP-in-pane deferral (`ExtraPaneState` now carries the
// `last_frame`/`rdp_w`/`rdp_h` fields a `Surface::Framebuffer` pane needs).
fn wire_connect_in_split_row(ctx: &Ctx) {
    ctx.ui.on_connect_in_split_row({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let toast_model = ctx.toast_model.clone();
        let toast_next_id = ctx.toast_next_id.clone();
        let hk_pending = ctx.hk_pending.clone();
        let cert_pending = ctx.cert_pending.clone();
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
                &cert_pending,
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
        let cred_model = ctx.cred_model.clone();
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
            // P9.5 #6: deleting a connection may drop a credential's "used by
            // N connections" count.
            keys_ctl::refresh_cred_model(&st, &cred_model);
        }
    });
}

/// Item (d): after a save, should the connection's OLD Inline secret (if
/// any) be deleted from the keychain? Only when it WAS Inline before this
/// save AND is no longer Inline now -- staying Inline (even across a
/// blank/untouched password field) must never touch the keychain entry it
/// still owns. Storage already deletes `conn:<id>:password` when the
/// connection itself is deleted (P9.6-A Decision 2); this is specifically the
/// mode-switch case, which is cm-ui's to handle.
pub(super) fn should_delete_inline_secret(old_was_inline: bool, new_cred_mode: i32) -> bool {
    old_was_inline && new_cred_mode != 1
}

/// P9.6-A Phase C: the `CredentialSource` to save, from the mode selector +
/// its mode-specific fields. `typed_password_present` is whether the caller's
/// (already-captured, about-to-be-cleared) transient password field was
/// non-empty -- true means "set/replace the stored secret", so `has_secret`
/// becomes true even for a connection that never had one; blank preserves
/// whatever `had_secret` already said (loaded from the enum's own flag when
/// the editor opened -- see `cred_mode_fields`). `domain` is Inline-only for
/// RDP (SSH has no use for it, per the P9.6 non-goals) -- `is_rdp` gates it
/// exactly like `profile_editor.slint`'s own Domain field.
pub(super) fn credential_source_from_form(
    cred_mode: i32,
    object_cred_id: Option<CredentialId>,
    inline_username: &str,
    inline_domain: &str,
    is_rdp: bool,
    typed_password_present: bool,
    had_secret: bool,
) -> Option<CredentialSource> {
    match cred_mode {
        1 => Some(CredentialSource::Inline {
            username: inline_username.trim().to_owned(),
            domain: if is_rdp {
                let d = inline_domain.trim();
                if d.is_empty() {
                    None
                } else {
                    Some(d.to_owned())
                }
            } else {
                None
            },
            has_secret: typed_password_present || had_secret,
        }),
        2 => Some(CredentialSource::Prompt),
        // 0 (Reference), and any other value defensively: today's behavior.
        _ => object_cred_id.map(CredentialSource::Object),
    }
}

fn wire_profile_save(ctx: &Ctx) {
    ctx.ui.on_profile_save({
        let state = ctx.state.clone();
        let conn_model = ctx.conn_model.clone();
        let cred_model = ctx.cred_model.clone();
        let repo_ps = ctx.repo.clone();
        let secrets_ps = ctx.secrets.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let mut form = ui.get_profile_form();
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
            // Item (d) handoff: was this connection Inline *before* this save?
            // (`form.id == 0` -- a brand-new connection -- can't have been.)
            let old_was_inline = {
                let st = state.borrow();
                st.conn_tree.conn_by_id(form.id as i64).is_some_and(|c| {
                    matches!(c.credential_source, Some(CredentialSource::Inline { .. }))
                })
            };
            let typed_password = form.inline_password.to_string();
            let credential_source = credential_source_from_form(
                form.cred_mode,
                cred_id,
                form.username.as_str(),
                form.rdp_domain.as_str(),
                kind == ConnectionKind::Rdp,
                !typed_password.is_empty(),
                form.inline_has_secret,
            );
            let conn = match Connection::new(
                ConnectionId::new(form.id as i64),
                group_id,
                form.name.to_string(),
                kind,
                settings,
                credential_source,
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
            // SECURITY: clear the transient inline-password field immediately
            // after capturing it above, before any further ops (mirrors
            // keys_ctl::wire_cred_save's secret-hygiene ordering).
            form.inline_password = SharedString::from("");
            ui.set_profile_form(form.clone());

            let saved_id = match repo_ps.upsert_connection(&conn) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!("upsert connection failed: {e}");
                    return;
                }
            };
            // A newly typed Inline password overwrites the stored secret
            // (keyed to the connection, never the SQLite row -- Decision 2).
            if form.cred_mode == 1 && !typed_password.is_empty() {
                let key_ref = CredentialRef::for_connection(saved_id, CredentialPurpose::Password);
                if let Err(e) = secrets_ps.store(&key_ref, &Secret::from_string(typed_password)) {
                    tracing::warn!("inline keychain store failed: {e}");
                }
            }
            // Item (d): switching AWAY from Inline deletes its keychain entry.
            if should_delete_inline_secret(old_was_inline, form.cred_mode) {
                let key_ref = CredentialRef::for_connection(saved_id, CredentialPurpose::Password);
                if let Err(e) = secrets_ps.delete(&key_ref) {
                    tracing::warn!("inline keychain delete-on-switch failed: {e}");
                }
            }

            ui.set_profile_editor_open(false);
            let mut st = state.borrow_mut();
            if let Err(e) = st.conn_tree.reload(repo_ps.as_ref()) {
                tracing::warn!("reload after save failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            refresh_group_name_list(&st, &ui);
            // P9.5 #6: a save here may change which credential a connection
            // directly references -- keep the Keys panel's "used by N
            // connections" badges in sync.
            keys_ctl::refresh_cred_model(&st, &cred_model);
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

/// .99 GPU verify (real double-click investigation): this used to
/// unconditionally `remove(0)` every existing row then `push` every row of
/// `flat` fresh, on EVERY call -- including the plain, non-structural
/// `row-selected` refresh a single click triggers (`wire_select_conn_row`,
/// above) to update the `selected` highlight. A `VecModel::remove`/`push`
/// pair is a STRUCTURAL model mutation Slint's `for conn[idx] in
/// connections: ConnectionRow {...}` repeater reacts to by destroying and
/// recreating the row's component instance (including its `touch`
/// TouchArea) -- so a plain single click on a row destroyed and rebuilt
/// that exact row's own `touch` out from under the pointer as a SIDE EFFECT
/// of merely selecting it. Slint's double-click detection tracks
/// `click_count` by comparing the CURRENT click's hit item to the item the
/// PREVIOUS click landed on (`i-slint-core`'s `send_mouse_event_to_item`);
/// since the row's `touch` was a brand-new instance by the time the second
/// click of a double-click landed, that comparison always failed, resetting
/// `click_count` to 0 -- so `double-clicked` (P9.5 #2's launch gesture)
/// could never fire on a real pointer, even though headless element tests
/// (which invoke `row-activated`/`row-selected` directly, bypassing Slint's
/// click-count machinery entirely) never exercised this at all.
///
/// Fixed by diffing instead of blindly rebuilding: `set_row_data` at a
/// stable index is a data-only update Slint's repeater applies to the
/// EXISTING component instance in place (no destroy/recreate), which keeps
/// `touch`'s identity stable across a plain selection change -- restoring
/// real-pointer double-click detection. Rows are only actually added/
/// removed (a genuine structural change: connect/delete/duplicate/reorder/
/// expand-collapse) at the tail, past whichever prefix already matches.
/// The actual decision is [`diff_conn_rows`], a pure function kept separate
/// so the "a plain selection-only change produces zero Push/RemoveLast ops"
/// claim above is directly unit-testable without a `VecModel`/`AppWindow`.
pub(super) fn refresh_conn_model(state: &State, conn_model: &Rc<VecModel<ConnRow>>) {
    let flat = state.conn_tree.flat_filtered(&state.conn_filter);
    let old: Vec<ConnRow> = (0..conn_model.row_count())
        .filter_map(|i| conn_model.row_data(i))
        .collect();
    for op in diff_conn_rows(&old, flat) {
        match op {
            RowOp::SetRowData(i, row) => conn_model.set_row_data(i, row),
            RowOp::Push(row) => conn_model.push(row),
            RowOp::RemoveLast => {
                conn_model.remove(conn_model.row_count() - 1);
            }
        }
    }
}

/// The minimal sequence of `VecModel` operations to turn `old` into `new`.
/// `SetRowData` (index unchanged, data updated in place -- Slint's repeater
/// reuses the existing component instance) is always preferred over
/// `Push`/`RemoveLast` (structural -- destroys/recreates it) for any index
/// present in both; only a genuine length change adds/removes at the tail.
#[derive(Debug, PartialEq)]
enum RowOp {
    SetRowData(usize, ConnRow),
    Push(ConnRow),
    RemoveLast,
}

fn diff_conn_rows(old: &[ConnRow], new: Vec<ConnRow>) -> Vec<RowOp> {
    let old_len = old.len();
    let new_len = new.len();
    let mut ops = Vec::new();
    for (i, row) in new.into_iter().enumerate() {
        if i < old_len {
            if old[i] != row {
                ops.push(RowOp::SetRowData(i, row));
            }
        } else {
            ops.push(RowOp::Push(row));
        }
    }
    for _ in new_len..old_len {
        ops.push(RowOp::RemoveLast);
    }
    ops
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

/// Returns `(kind, host, port, username, auth_method, rdp_domain, rdp_resolution)`.
/// `rdp_domain`/`rdp_resolution` are only meaningful for `kind == 1` (RDP);
/// SSH/Local return them empty/default since the editor hides those fields
/// for those kinds (P7.2, gap #2).
pub(super) fn profile_fields_from_conn(
    conn: &Connection,
) -> (i32, String, String, String, i32, String, String) {
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
            String::new(),
            default_rdp_resolution(),
        ),
        ConnectionSettings::Rdp(s) => (
            1,
            s.host.clone(),
            s.port.to_string(),
            s.username.clone().unwrap_or_default(),
            1,
            s.domain.clone().unwrap_or_default(),
            format!("{}x{}", s.width, s.height),
        ),
        ConnectionSettings::Local(_) => (
            2,
            String::new(),
            String::new(),
            String::new(),
            1,
            String::new(),
            default_rdp_resolution(),
        ),
    }
}

/// Default "WIDTHxHEIGHT" string shown/stored when a form has never had an
/// RDP resolution set -- matches QuickConnectForm's default (screens/dialogs.slint).
pub(super) fn default_rdp_resolution() -> String {
    format!(
        "{}x{}",
        RdpSettings::DEFAULT_WIDTH,
        RdpSettings::DEFAULT_HEIGHT
    )
}

pub(super) fn settings_from_form(form: &ConnProfile) -> ConnectionSettings {
    match form.kind {
        1 => {
            let (width, height) = sessions::parse_qc_resolution(form.rdp_resolution.as_str());
            ConnectionSettings::Rdp(RdpSettings {
                host: form.host.to_string(),
                port: form
                    .port
                    .as_str()
                    .parse::<u16>()
                    .unwrap_or(RdpSettings::DEFAULT_PORT),
                domain: {
                    let d = form.rdp_domain.trim().to_owned();
                    if d.is_empty() { None } else { Some(d) }
                },
                username: {
                    let u = form.username.trim().to_owned();
                    if u.is_empty() { None } else { Some(u) }
                },
                width,
                height,
                color_depth: RdpSettings::default().color_depth,
            })
        }
        2 => ConnectionSettings::Local(LocalSettings::default()),
        _ => ConnectionSettings::Ssh(SshSettings {
            host: form.host.to_string(),
            port: form
                .port
                .as_str()
                .parse::<u16>()
                .unwrap_or(SshSettings::DEFAULT_PORT),
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

    use cm_core::{CredentialStore, Secret};

    use super::*;

    // ── .99 GPU verify: refresh_conn_model's diff (double-click fix) ──────

    fn conn_row(id: i32, label: &str, selected: bool) -> ConnRow {
        ConnRow {
            id,
            label: SharedString::from(label),
            host: SharedString::from("host"),
            kind: SharedString::from("SSH"),
            status: SharedString::from("disconnected"),
            is_group: false,
            expanded: false,
            selected,
            depth: 0,
        }
    }

    #[test]
    fn diff_conn_rows_is_a_no_op_when_nothing_changed() {
        let rows = vec![conn_row(1, "a", false), conn_row(2, "b", true)];
        assert_eq!(diff_conn_rows(&rows, rows.clone()), Vec::<RowOp>::new());
    }

    #[test]
    fn diff_conn_rows_produces_only_set_row_data_when_only_selection_changes() {
        // The double-click regression's whole fix: a plain row-selected
        // refresh (nothing added/removed/reordered, just two rows' `selected`
        // flags flipping) must produce ONLY SetRowData ops -- never a
        // Push/RemoveLast, which would destroy and recreate the row's
        // `touch` TouchArea and break Slint's real-pointer double-click
        // detection (see `refresh_conn_model`'s doc comment for the full
        // mechanism this proves).
        let old = vec![
            conn_row(1, "a", false),
            conn_row(2, "b", true),
            conn_row(3, "c", false),
        ];
        let new = vec![
            conn_row(1, "a", true),
            conn_row(2, "b", false),
            conn_row(3, "c", false),
        ];
        assert_eq!(
            diff_conn_rows(&old, new.clone()),
            vec![
                RowOp::SetRowData(0, new[0].clone()),
                RowOp::SetRowData(1, new[1].clone()),
            ]
        );
    }

    #[test]
    fn diff_conn_rows_appends_new_rows_at_the_tail_when_the_list_grows() {
        let old = vec![conn_row(1, "a", false)];
        let new = vec![conn_row(1, "a", false), conn_row(2, "b", false)];
        assert_eq!(
            diff_conn_rows(&old, new.clone()),
            vec![RowOp::Push(new[1].clone())]
        );
    }

    #[test]
    fn diff_conn_rows_removes_from_the_tail_when_the_list_shrinks() {
        let old = vec![conn_row(1, "a", false), conn_row(2, "b", false)];
        let new = vec![conn_row(1, "a", false)];
        assert_eq!(diff_conn_rows(&old, new), vec![RowOp::RemoveLast]);
    }

    #[test]
    fn form_to_ssh_auth_password() {
        let auth_method: i32 = 1;
        let secret_raw = "test-secret".to_owned();
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
            Some(CredentialSource::Object(CredentialId::new(9))),
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
        assert_eq!(dup.credential_source, src.credential_source);
        assert_eq!(dup.sort, 4);
        assert_eq!(dup.created_at, 2_000);
        assert_eq!(dup.updated_at, 2_000);
    }

    #[test]
    fn duplicate_connection_inline_reports_no_secret_on_the_copy() {
        // The pure mapping function has no store handle to copy the actual
        // keychain secret -- `has_secret` starts false regardless of the
        // source's own flag. `copy_inline_secret_on_duplicate` (the caller's
        // follow-up, tested below) is what corrects it after a real copy.
        let src = Connection::new(
            ConnectionId::new(5),
            None,
            "inline-conn".to_owned(),
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(SshSettings {
                host: "10.0.0.9".to_owned(),
                port: 22,
                username: "root".to_owned(),
                auth_method: SshAuthMethod::Password,
            }),
            Some(CredentialSource::Inline {
                username: "root".to_owned(),
                domain: None,
                has_secret: true,
            }),
            0,
            0,
            0,
        )
        .unwrap();

        let dup = duplicate_connection(&src, 1, 100).unwrap();

        assert_eq!(
            dup.credential_source,
            Some(CredentialSource::Inline {
                username: "root".to_owned(),
                domain: None,
                has_secret: false,
            })
        );
    }

    // -- copy_inline_secret_on_duplicate ---------------------------------------

    /// Minimal `(service, account) -> bytes` `CredentialStore` double -- just
    /// enough to prove `copy_inline_secret_on_duplicate` actually reads the
    /// source key and writes the destination key, without pulling in a real
    /// OS keychain.
    struct MapStore(std::sync::Mutex<std::collections::HashMap<(String, String), Vec<u8>>>);

    impl MapStore {
        fn new() -> Self {
            Self(std::sync::Mutex::new(std::collections::HashMap::new()))
        }
    }

    impl cm_core::CredentialStore for MapStore {
        fn store(
            &self,
            key: &CredentialRef,
            secret: &Secret,
        ) -> Result<(), cm_core::CredentialError> {
            self.0.lock().unwrap().insert(
                (key.service().to_owned(), key.account().to_owned()),
                secret.expose().to_vec(),
            );
            Ok(())
        }

        fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, cm_core::CredentialError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(&(key.service().to_owned(), key.account().to_owned()))
                .cloned()
                .map(Secret::new))
        }

        fn delete(&self, key: &CredentialRef) -> Result<(), cm_core::CredentialError> {
            self.0
                .lock()
                .unwrap()
                .remove(&(key.service().to_owned(), key.account().to_owned()));
            Ok(())
        }
    }

    #[test]
    fn copy_inline_secret_on_duplicate_copies_the_secret_and_flips_has_secret() {
        use cm_core::ConnectionRepository;
        let repo = cm_storage::SqliteRepository::open_in_memory().expect("open in-memory db");

        let src = Connection::new(
            ConnectionId::new(0),
            None,
            "inline-conn".to_owned(),
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(SshSettings {
                host: "10.0.0.9".to_owned(),
                port: 22,
                username: "root".to_owned(),
                auth_method: SshAuthMethod::Password,
            }),
            Some(CredentialSource::Inline {
                username: "root".to_owned(),
                domain: None,
                has_secret: true,
            }),
            0,
            0,
            0,
        )
        .unwrap();
        let src_id = repo.upsert_connection(&src).expect("insert source");

        let store = MapStore::new();
        store
            .store(
                &CredentialRef::for_connection(src_id, CredentialPurpose::Password),
                &Secret::from_string("s3cret".to_owned()),
            )
            .unwrap();

        // The duplicate as `duplicate_connection` + the caller's insert would
        // leave it: fresh id assigned by the repo, has_secret still false.
        let dup = duplicate_connection(&src, 1, 100).unwrap();
        let new_id = repo.upsert_connection(&dup).expect("insert duplicate");

        copy_inline_secret_on_duplicate(&repo, &store, &dup, src_id, new_id);

        let copied = store
            .get(&CredentialRef::for_connection(
                new_id,
                CredentialPurpose::Password,
            ))
            .unwrap()
            .expect("secret should have been copied to the new connection's key");
        assert_eq!(copied.expose(), b"s3cret");

        let persisted = repo
            .get_connection(new_id)
            .expect("load duplicate")
            .expect("duplicate exists");
        assert_eq!(
            persisted.credential_source,
            Some(CredentialSource::Inline {
                username: "root".to_owned(),
                domain: None,
                has_secret: true,
            }),
            "has_secret must be persisted as true once the secret is actually copied"
        );
    }

    #[test]
    fn copy_inline_secret_on_duplicate_is_a_no_op_when_source_has_no_stored_secret() {
        use cm_core::ConnectionRepository;
        let repo = cm_storage::SqliteRepository::open_in_memory().expect("open in-memory db");
        let src = Connection::new(
            ConnectionId::new(0),
            None,
            "inline-conn".to_owned(),
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(SshSettings {
                host: "10.0.0.9".to_owned(),
                port: 22,
                username: "root".to_owned(),
                auth_method: SshAuthMethod::Password,
            }),
            Some(CredentialSource::Inline {
                username: "root".to_owned(),
                domain: None,
                has_secret: true,
            }),
            0,
            0,
            0,
        )
        .unwrap();
        let src_id = repo.upsert_connection(&src).expect("insert source");
        // Nothing actually stored under `src_id`'s key -- a real-world
        // "has_secret said true but the keychain entry is gone" edge case.
        let store = MapStore::new();

        let dup = duplicate_connection(&src, 1, 100).unwrap();
        let new_id = repo.upsert_connection(&dup).expect("insert duplicate");

        copy_inline_secret_on_duplicate(&repo, &store, &dup, src_id, new_id);

        let persisted = repo
            .get_connection(new_id)
            .expect("load duplicate")
            .expect("duplicate exists");
        assert_eq!(
            persisted.credential_source,
            Some(CredentialSource::Inline {
                username: "root".to_owned(),
                domain: None,
                has_secret: false,
            }),
            "nothing to copy -- has_secret stays false, exactly as duplicate_connection left it"
        );
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

    // Baseline ConnProfile builder for the settings_from_form/profile_fields_from_conn
    // tests below -- keeps each test focused on the field(s) it actually varies.
    fn base_profile_form() -> ConnProfile {
        ConnProfile {
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
            effective_cred_username: SharedString::from(""),
            effective_inherited: false,
            selected_group_idx: 0,
            rdp_domain: SharedString::from(""),
            rdp_resolution: SharedString::from(""),
            cred_mode: 0,
            inline_password: SharedString::from(""),
            inline_has_secret: false,
        }
    }

    #[test]
    fn profile_form_mapping_ssh() {
        let form = base_profile_form();
        let settings = settings_from_form(&form);
        assert!(
            matches!(
                settings,
                ConnectionSettings::Ssh(SshSettings { port: 2222, .. })
            ),
            "SSH settings port should be 2222"
        );
    }

    #[test]
    fn ssh_kind_falls_back_to_default_port_on_garbage() {
        let mut form = base_profile_form();
        form.port = SharedString::from("not-a-port");
        let settings = settings_from_form(&form);
        assert!(matches!(
            settings,
            ConnectionSettings::Ssh(SshSettings { port: 22, .. })
        ));
    }

    // ── P7.2: RDP-kind field manifest / default port mapping ────────────────

    #[test]
    fn rdp_kind_defaults_to_port_3389_on_garbage() {
        let mut form = base_profile_form();
        form.kind = 1;
        form.port = SharedString::from("");
        let settings = settings_from_form(&form);
        assert!(matches!(
            settings,
            ConnectionSettings::Rdp(RdpSettings { port: 3389, .. })
        ));
    }

    #[test]
    fn rdp_kind_maps_domain_and_resolution() {
        let mut form = base_profile_form();
        form.kind = 1;
        form.host = SharedString::from("win11-tgt");
        form.port = SharedString::from("3389");
        form.username = SharedString::from("administrator");
        form.rdp_domain = SharedString::from("CORP");
        form.rdp_resolution = SharedString::from("1920x1080");
        let settings = settings_from_form(&form);
        match settings {
            ConnectionSettings::Rdp(s) => {
                assert_eq!(s.host, "win11-tgt");
                assert_eq!(s.port, 3389);
                assert_eq!(s.domain.as_deref(), Some("CORP"));
                assert_eq!(s.username.as_deref(), Some("administrator"));
                assert_eq!(s.width, 1920);
                assert_eq!(s.height, 1080);
            }
            other => panic!("expected RDP settings, got {other:?}"),
        }
    }

    #[test]
    fn rdp_kind_empty_domain_and_garbage_resolution_fall_back() {
        let mut form = base_profile_form();
        form.kind = 1;
        form.rdp_domain = SharedString::from("   ");
        form.rdp_resolution = SharedString::from("garbage");
        let settings = settings_from_form(&form);
        match settings {
            ConnectionSettings::Rdp(s) => {
                assert_eq!(s.domain, None, "blank domain should map to None");
                assert_eq!(s.width, RdpSettings::DEFAULT_WIDTH);
                assert_eq!(s.height, RdpSettings::DEFAULT_HEIGHT);
            }
            other => panic!("expected RDP settings, got {other:?}"),
        }
    }

    #[test]
    fn profile_fields_from_conn_round_trips_rdp_domain_and_resolution() {
        let settings = ConnectionSettings::Rdp(RdpSettings {
            host: "10.0.0.5".to_owned(),
            port: 3389,
            domain: Some("CORP".to_owned()),
            username: Some("admin".to_owned()),
            width: 1024,
            height: 768,
            color_depth: RdpSettings::default().color_depth,
        });
        let conn = Connection::new(
            ConnectionId::new(1),
            None,
            "rdp-conn".to_owned(),
            ConnectionKind::Rdp,
            settings,
            None,
            0,
            0,
            0,
        )
        .expect("valid RDP connection");
        let (kind, host, port, username, auth_method, rdp_domain, rdp_resolution) =
            profile_fields_from_conn(&conn);
        assert_eq!(kind, 1);
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, "3389");
        assert_eq!(username, "admin");
        assert_eq!(auth_method, 1);
        assert_eq!(rdp_domain, "CORP");
        assert_eq!(rdp_resolution, "1024x768");
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

    // -- cred_mode_fields / credential_source_from_form (P9.6-A Phase C) ------

    #[test]
    fn cred_mode_fields_none_and_object_are_reference_mode() {
        assert_eq!(cred_mode_fields(&None), (0, None, None, false));
        assert_eq!(
            cred_mode_fields(&Some(CredentialSource::Object(CredentialId::new(9)))),
            (0, None, None, false)
        );
    }

    #[test]
    fn cred_mode_fields_prompt_is_mode_two_with_no_overrides() {
        assert_eq!(
            cred_mode_fields(&Some(CredentialSource::Prompt)),
            (2, None, None, false)
        );
    }

    #[test]
    fn cred_mode_fields_inline_is_mode_one_with_its_own_username_and_domain() {
        let source = Some(CredentialSource::Inline {
            username: "alice".to_owned(),
            domain: Some("CORP".to_owned()),
            has_secret: true,
        });
        assert_eq!(
            cred_mode_fields(&source),
            (1, Some("alice".to_owned()), Some("CORP".to_owned()), true)
        );
    }

    #[test]
    fn credential_source_from_form_reference_mode_maps_dropdown_selection() {
        // mode 0 (Reference): same as pre-P9.6-A -- `None` selection means
        // inherit, `Some(id)` an explicit Object.
        assert_eq!(
            credential_source_from_form(0, None, "", "", false, false, false),
            None
        );
        assert_eq!(
            credential_source_from_form(0, Some(CredentialId::new(3)), "", "", false, false, false),
            Some(CredentialSource::Object(CredentialId::new(3)))
        );
    }

    #[test]
    fn credential_source_from_form_prompt_mode_ignores_every_other_field() {
        assert_eq!(
            credential_source_from_form(
                2,
                Some(CredentialId::new(3)),
                "bob",
                "CORP",
                true,
                true,
                true
            ),
            Some(CredentialSource::Prompt)
        );
    }

    #[test]
    fn credential_source_from_form_inline_ssh_never_carries_a_domain() {
        // Domain is RDP-only, per the P9.6 non-goals -- `is_rdp: false` drops
        // even a non-empty typed domain.
        let source = credential_source_from_form(1, None, "bob", "CORP", false, true, false);
        assert_eq!(
            source,
            Some(CredentialSource::Inline {
                username: "bob".to_owned(),
                domain: None,
                has_secret: true,
            })
        );
    }

    #[test]
    fn credential_source_from_form_inline_rdp_keeps_a_trimmed_non_empty_domain() {
        let source = credential_source_from_form(1, None, "bob", "  CORP  ", true, false, false);
        assert_eq!(
            source,
            Some(CredentialSource::Inline {
                username: "bob".to_owned(),
                domain: Some("CORP".to_owned()),
                has_secret: false,
            })
        );
    }

    #[test]
    fn credential_source_from_form_inline_has_secret_survives_a_blank_password_when_one_was_already_stored()
     {
        // Leaving the password field blank on an edit must NOT read back as
        // "no secret" when one is already in the keychain (item d's sibling
        // concern: don't silently drop a stored secret on an untouched save).
        let source = credential_source_from_form(1, None, "bob", "", false, false, true);
        assert_eq!(
            source,
            Some(CredentialSource::Inline {
                username: "bob".to_owned(),
                domain: None,
                has_secret: true,
            })
        );
    }

    #[test]
    fn credential_source_from_form_inline_no_secret_when_never_typed_or_stored() {
        let source = credential_source_from_form(1, None, "bob", "", false, false, false);
        assert_eq!(
            source,
            Some(CredentialSource::Inline {
                username: "bob".to_owned(),
                domain: None,
                has_secret: false,
            })
        );
    }

    // -- should_delete_inline_secret (item d) ----------------------------------

    #[test]
    fn should_delete_inline_secret_switching_away_from_inline() {
        assert!(should_delete_inline_secret(true, 0)); // -> Reference
        assert!(should_delete_inline_secret(true, 2)); // -> Prompt
    }

    #[test]
    fn should_delete_inline_secret_staying_inline_never_deletes() {
        // Even across a blank/untouched password field on this save -- the
        // keychain entry it already owns must survive.
        assert!(!should_delete_inline_secret(true, 1));
    }

    #[test]
    fn should_delete_inline_secret_was_not_inline_nothing_to_delete() {
        assert!(!should_delete_inline_secret(false, 0));
        assert!(!should_delete_inline_secret(false, 1));
        assert!(!should_delete_inline_secret(false, 2));
    }
}
