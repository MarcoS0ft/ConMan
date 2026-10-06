use crate::generated_ui::{ConnProfile, CredFormData, GroupForm};
use cm_core::application::{
    AppCommand, CredentialSecretIntent, InlineSecretIntent, MutationMeta, SecretChange,
    WorkspaceDto, WorkspaceMutation,
};
use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialFolder,
    CredentialFolderId, CredentialId, CredentialKind, CredentialSource, Group, GroupId,
    LocalSettings, RdpSettings, SshAuthMethod, SshSettings, TelnetSettings,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::rc::Rc;

use super::{PendingUiAction, SharedUiState};

fn build_group_name_list(groups: &[cm_core::Group]) -> Vec<SharedString> {
    let mut sorted: Vec<&cm_core::Group> = groups.iter().collect();
    sorted.sort_by_key(|group| (group.sort, group.id.get()));
    let mut names = vec![SharedString::from("Root (no group)")];
    names.extend(
        sorted
            .into_iter()
            .map(|group| SharedString::from(group.name.as_str())),
    );
    names
}

pub(super) fn install_workspace_models(ui: &crate::AppWindow, workspace: &WorkspaceDto) {
    let tree =
        crate::tree::ConnectionTree::new(workspace.groups.clone(), workspace.connections.clone());
    let keys = crate::keys::KeysPanel::new(
        workspace.credential_folders.clone(),
        workspace.credentials.clone(),
    );
    let connections = Rc::new(VecModel::from(tree.flat()));
    let credentials = Rc::new(VecModel::from(keys.flat()));
    ui.set_connections(ModelRc::from(connections));
    ui.set_credentials(ModelRc::from(credentials));
    ui.set_group_name_list(ModelRc::from(Rc::new(VecModel::from(
        build_group_name_list(&workspace.groups),
    ))));
    ui.set_cred_name_list(ModelRc::from(Rc::new(VecModel::from(
        crate::tree::build_cred_name_list(
            &workspace.credentials,
            &workspace.credential_folders,
            "Inherit from group",
        ),
    ))));
    ui.set_folder_name_list(ModelRc::from(Rc::new(VecModel::from(
        crate::keys::KeysPanel::build_folder_name_list(&workspace.credential_folders),
    ))));
    ui.set_cred_folder_parent_name_list(ModelRc::from(Rc::new(VecModel::from(
        crate::keys::KeysPanel::build_folder_name_list(&workspace.credential_folders),
    ))));
}

pub(super) fn wire_workspace(ui: &crate::AppWindow, shared: &SharedUiState) {
    wire_editor_tracking(ui, shared);
    wire_new_connection(ui, shared);
    wire_edit_connection(ui, shared);
    wire_profile_save(ui, shared);
    wire_new_group(ui, shared);
    wire_edit_group(ui, shared);
    wire_group_save(ui, shared);
    wire_new_credential(ui, shared);
    wire_edit_credential(ui, shared);
    wire_credential_save(ui, shared);
    wire_delete_connection(ui, shared);
    wire_delete_credential(ui, shared);
    wire_new_credential_folder(ui, shared);
    wire_edit_credential_folder(ui, shared);
    wire_save_credential_folder(ui, shared);
    wire_reorder_conn_group(ui, shared);
    wire_reorder_credential_folder(ui, shared);
}

fn wire_editor_tracking(ui: &crate::AppWindow, shared: &SharedUiState) {
    macro_rules! edited {
        ($callback:ident, $kind:expr, $error:ident) => {{
            let state = shared.clone();
            let weak = ui.as_weak();
            ui.$callback(move || {
                if let Some(editor) = state.borrow_mut().editor_mut($kind).as_mut() {
                    editor.edit_generation = editor.edit_generation.wrapping_add(1);
                }
                if let Some(ui) = weak.upgrade() {
                    ui.$error(SharedString::default());
                }
            });
        }};
    }
    edited!(
        on_profile_form_edited,
        super::state::EditorKind::Profile,
        set_profile_save_error
    );
    edited!(
        on_group_form_edited,
        super::state::EditorKind::Group,
        set_group_save_error
    );
    edited!(
        on_cred_form_edited,
        super::state::EditorKind::Credential,
        set_cred_save_error
    );
    edited!(
        on_cred_folder_form_edited,
        super::state::EditorKind::CredentialFolder,
        set_cred_folder_save_error
    );
    macro_rules! cancelled {
        ($callback:ident, $kind:expr) => {{
            let state = shared.clone();
            let weak = ui.as_weak();
            ui.$callback(move || {
                *state.borrow_mut().editor_mut($kind) = None;
                if let Some(ui) = weak.upgrade() {
                    super::set_editor_pending(&ui, $kind, false);
                }
            });
        }};
    }
    cancelled!(
        on_profile_editor_cancelled,
        super::state::EditorKind::Profile
    );
    cancelled!(on_group_editor_cancelled, super::state::EditorKind::Group);
    cancelled!(
        on_cred_editor_cancelled,
        super::state::EditorKind::Credential
    );
    cancelled!(
        on_cred_folder_editor_cancelled,
        super::state::EditorKind::CredentialFolder
    );
}

fn begin_editor(shared: &SharedUiState, ui: &crate::AppWindow, kind: super::state::EditorKind) {
    shared.borrow_mut().open_editor(kind);
    super::set_editor_pending(ui, kind, false);
    super::set_editor_error(ui, kind, "");
}

fn editor_ticket(
    shared: &SharedUiState,
    kind: super::state::EditorKind,
) -> Option<super::state::EditorCorrelation> {
    shared
        .borrow()
        .editor(kind)
        .map(|e| super::state::EditorCorrelation {
            kind,
            instance: e.instance,
            edit_generation: e.edit_generation,
        })
}

fn group_at_index(index: i32, groups: &[Group]) -> Option<GroupId> {
    if index <= 0 {
        return None;
    }
    let mut values: Vec<&Group> = groups.iter().collect();
    values.sort_by_key(|group| (group.sort, group.id.get()));
    values.get((index - 1) as usize).map(|group| group.id)
}

fn group_index(id: Option<GroupId>, groups: &[Group]) -> i32 {
    let Some(id) = id else { return 0 };
    let mut values: Vec<&Group> = groups.iter().collect();
    values.sort_by_key(|group| (group.sort, group.id.get()));
    values
        .iter()
        .position(|group| group.id == id)
        .map(|idx| idx as i32 + 1)
        .unwrap_or(0)
}

fn credential_at_index(
    index: i32,
    credentials: &[Credential],
    folders: &[CredentialFolder],
) -> Option<CredentialId> {
    if index <= 0 {
        return None;
    }
    let mut values: Vec<&Credential> = credentials
        .iter()
        .filter(|cred| cred.folder_id.is_none())
        .collect();
    values.sort_by_key(|cred| &cred.name);
    let root_count = values.len();
    if (index as usize) <= root_count {
        return values.get(index as usize - 1).map(|cred| cred.id);
    }
    let mut at = root_count;
    for folder in folders {
        let mut children: Vec<&Credential> = credentials
            .iter()
            .filter(|cred| cred.folder_id == Some(folder.id))
            .collect();
        children.sort_by_key(|cred| &cred.name);
        for child in children {
            at += 1;
            if at == index as usize {
                return Some(child.id);
            }
        }
    }
    None
}

fn credential_index(
    id: Option<CredentialId>,
    credentials: &[Credential],
    folders: &[CredentialFolder],
) -> i32 {
    let Some(id) = id else { return 0 };
    let mut at = 0_i32;
    let mut root: Vec<&Credential> = credentials
        .iter()
        .filter(|cred| cred.folder_id.is_none())
        .collect();
    root.sort_by_key(|cred| &cred.name);
    for cred in root {
        at += 1;
        if cred.id == id {
            return at;
        }
    }
    for folder in folders {
        let mut children: Vec<&Credential> = credentials
            .iter()
            .filter(|cred| cred.folder_id == Some(folder.id))
            .collect();
        children.sort_by_key(|cred| &cred.name);
        for cred in children {
            at += 1;
            if cred.id == id {
                return at;
            }
        }
    }
    0
}

fn folder_at_index(index: i32, folders: &[CredentialFolder]) -> Option<CredentialFolderId> {
    if index <= 0 {
        return None;
    }
    let mut values: Vec<&CredentialFolder> = folders.iter().collect();
    values.sort_by_key(|folder| (folder.sort, folder.id.get()));
    values.get((index - 1) as usize).map(|folder| folder.id)
}

fn folder_index(id: Option<CredentialFolderId>, folders: &[CredentialFolder]) -> i32 {
    let Some(id) = id else { return 0 };
    let mut values: Vec<&CredentialFolder> = folders.iter().collect();
    values.sort_by_key(|folder| (folder.sort, folder.id.get()));
    values
        .iter()
        .position(|folder| folder.id == id)
        .map(|idx| idx as i32 + 1)
        .unwrap_or(0)
}

fn next_sort<T>(values: impl Iterator<Item = T>, sort: impl Fn(T) -> i64) -> Option<i64> {
    values
        .map(sort)
        .max()
        .map(|max| max.checked_add(1))
        .unwrap_or(Some(0))
}

fn wire_new_connection(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_new_connection(move |parent| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(parent_id) = crate::domain_ui_id::parse_optional_group_id(parent.as_str()) else {
            super::push_toast(&ui, &state, "Invalid parent group ID.");
            return;
        };
        let workspace = state.borrow().workspace.clone();
        let Some(workspace) = workspace else { return };
        let form = ConnProfile {
            id: SharedString::default(),
            name: "New Connection".into(),
            group_id: parent_id
                .map(crate::domain_ui_id::group_id_text)
                .unwrap_or_default(),
            kind: 0,
            host: "".into(),
            port: "22".into(),
            username: "".into(),
            auth_method: 1,
            selected_cred_idx: 0,
            effective_cred_name: "".into(),
            effective_cred_username: "".into(),
            effective_inherited: false,
            selected_group_idx: group_index(parent_id, &workspace.groups),
            rdp_domain: "".into(),
            rdp_resolution: format!(
                "{}x{}",
                RdpSettings::DEFAULT_WIDTH,
                RdpSettings::DEFAULT_HEIGHT
            )
            .into(),
            cred_mode: 0,
            inline_password: "".into(),
            inline_has_secret: false,
        };
        ui.set_profile_form(form);
        begin_editor(&state, &ui, super::state::EditorKind::Profile);
        ui.set_profile_editor_open(true);
    });
}

fn wire_edit_connection(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_edit_conn(move |raw| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(id) = crate::domain_ui_id::parse_connection_id(raw.as_str()) else {
            return;
        };
        let Some(workspace) = state.borrow().workspace.clone() else {
            return;
        };
        let Some(conn) = workspace.connections.iter().find(|conn| conn.id == id) else {
            return;
        };
        let (kind, host, port, username, auth_method, domain, resolution) = profile_values(conn);
        let (cred_mode, direct_cred, inline_user, inline_domain, has_secret) =
            match &conn.credential_source {
                Some(CredentialSource::Inline {
                    username,
                    domain,
                    has_secret,
                }) => (1, None, Some(username.clone()), domain.clone(), *has_secret),
                Some(CredentialSource::Prompt) => (2, None, None, None, false),
                Some(CredentialSource::Object(id)) => (0, Some(*id), None, None, false),
                None => (0, None, None, None, false),
            };
        let username = inline_user.unwrap_or(username);
        let domain = inline_domain.unwrap_or(domain);
        let eff = direct_cred.or_else(|| {
            conn.group_id
                .and_then(|gid| inherited_credential(gid, &workspace.groups))
        });
        let form = ConnProfile {
            id: crate::domain_ui_id::connection_id_text(conn.id),
            name: conn.name.clone().into(),
            group_id: conn
                .group_id
                .map(crate::domain_ui_id::group_id_text)
                .unwrap_or_default(),
            kind,
            host: host.into(),
            port: port.into(),
            username: username.into(),
            auth_method,
            selected_cred_idx: credential_index(
                direct_cred,
                &workspace.credentials,
                &workspace.credential_folders,
            ),
            effective_cred_name: eff
                .and_then(|id| workspace.credentials.iter().find(|c| c.id == id))
                .map(|c| c.name.clone())
                .unwrap_or_default()
                .into(),
            effective_cred_username: eff
                .and_then(|id| workspace.credentials.iter().find(|c| c.id == id))
                .and_then(|c| c.username.clone())
                .unwrap_or_default()
                .into(),
            effective_inherited: direct_cred.is_none() && eff.is_some(),
            selected_group_idx: group_index(conn.group_id, &workspace.groups),
            rdp_domain: domain.into(),
            rdp_resolution: resolution.into(),
            cred_mode,
            inline_password: "".into(),
            inline_has_secret: has_secret,
        };
        ui.set_profile_form(form);
        begin_editor(&state, &ui, super::state::EditorKind::Profile);
        ui.set_profile_editor_open(true);
    });
}

fn profile_values(conn: &Connection) -> (i32, String, String, String, i32, String, String) {
    match &conn.settings {
        ConnectionSettings::Ssh(v) => (
            0,
            v.host.clone(),
            v.port.to_string(),
            v.username.clone(),
            match v.auth_method {
                SshAuthMethod::Password => 1,
                SshAuthMethod::Agent => 2,
                SshAuthMethod::PublicKey { .. } => 0,
            },
            String::new(),
            format!(
                "{}x{}",
                RdpSettings::DEFAULT_WIDTH,
                RdpSettings::DEFAULT_HEIGHT
            ),
        ),
        ConnectionSettings::Rdp(v) => (
            1,
            v.host.clone(),
            v.port.to_string(),
            v.username.clone().unwrap_or_default(),
            1,
            v.domain.clone().unwrap_or_default(),
            format!("{}x{}", v.width, v.height),
        ),
        ConnectionSettings::Telnet(v) => (
            2,
            v.host.clone(),
            v.port.to_string(),
            String::new(),
            1,
            String::new(),
            format!(
                "{}x{}",
                RdpSettings::DEFAULT_WIDTH,
                RdpSettings::DEFAULT_HEIGHT
            ),
        ),
        ConnectionSettings::Local(_) => (
            3,
            String::new(),
            String::new(),
            String::new(),
            1,
            String::new(),
            format!(
                "{}x{}",
                RdpSettings::DEFAULT_WIDTH,
                RdpSettings::DEFAULT_HEIGHT
            ),
        ),
    }
}

fn inherited_credential(mut group_id: GroupId, groups: &[Group]) -> Option<CredentialId> {
    for _ in 0..=groups.len() {
        let group = groups.iter().find(|group| group.id == group_id)?;
        if group.default_credential.is_some() {
            return group.default_credential;
        }
        group_id = group.parent_id?;
    }
    None
}

fn wire_profile_save(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_profile_save(move || {
        let Some(ui) = weak.upgrade() else { return };
        let mut form = ui.get_profile_form();
        let Ok(id) = crate::domain_ui_id::parse_connection_form_id(form.id.as_str()) else {
            super::push_toast(&ui, &state, "Invalid connection ID.");
            return;
        };
        let Ok(_raw_group) = crate::domain_ui_id::parse_optional_group_id(form.group_id.as_str())
        else {
            super::push_toast(&ui, &state, "Invalid group ID.");
            return;
        };
        let workspace = state.borrow().workspace.clone();
        let Some(workspace) = workspace else { return };
        let group_id = group_at_index(form.selected_group_idx, &workspace.groups);
        if form.selected_group_idx > 0 && group_id.is_none() {
            super::push_toast(&ui, &state, "The selected group no longer exists.");
            return;
        }
        let kind = match form.kind {
            1 => ConnectionKind::Rdp,
            2 => ConnectionKind::Telnet,
            3 => ConnectionKind::LocalTerminal,
            _ => ConnectionKind::Ssh,
        };
        let settings = match profile_settings(&form, kind) {
            Ok(value) => value,
            Err(error) => {
                super::push_toast(&ui, &state, &error);
                return;
            }
        };
        let direct = credential_at_index(
            form.selected_cred_idx,
            &workspace.credentials,
            &workspace.credential_folders,
        );
        let source = match form.cred_mode {
            1 => Some(CredentialSource::Inline {
                username: form.username.trim().to_owned(),
                domain: if kind == ConnectionKind::Rdp && !form.rdp_domain.trim().is_empty() {
                    Some(form.rdp_domain.trim().to_owned())
                } else {
                    None
                },
                has_secret: !form.inline_password.is_empty() || form.inline_has_secret,
            }),
            2 => Some(CredentialSource::Prompt),
            _ => direct.map(CredentialSource::Object),
        };
        let sibling = workspace
            .connections
            .iter()
            .filter(|c| c.group_id == group_id && c.id != id)
            .map(|c| c.sort)
            .max();
        let Some(sort) = sibling.map_or(Some(0), |v| v.checked_add(1)) else {
            super::push_toast(&ui, &state, "Connection ordering is exhausted.");
            return;
        };
        let now = now_secs();
        let created = workspace
            .connections
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.created_at)
            .unwrap_or(now);
        let connection = match Connection::new(
            id,
            group_id,
            form.name.to_string(),
            kind,
            settings,
            source,
            sort,
            created,
            now,
        ) {
            Ok(v) => v,
            Err(e) => {
                super::push_toast(&ui, &state, &format!("Invalid connection: {e}"));
                return;
            }
        };
        let password = form.inline_password.to_string();
        let secret_intent = if password.is_empty() {
            if id == ConnectionId::UNSAVED {
                InlineSecretIntent::Clear
            } else {
                InlineSecretIntent::Keep
            }
        } else {
            InlineSecretIntent::Replace(cm_core::Secret::from_string(password))
        };
        let correlation = editor_ticket(&state, super::state::EditorKind::Profile);
        let accepted = submit_editor_mutation(
            &ui,
            &state,
            WorkspaceMutation::UpsertConnection {
                value: connection,
                secret_intent,
            },
            correlation,
        );
        if accepted.is_some() {
            form.inline_password = SharedString::default();
            ui.set_profile_form(form);
        }
    });
}

fn profile_settings(
    form: &ConnProfile,
    kind: ConnectionKind,
) -> Result<ConnectionSettings, String> {
    let port = form
        .port
        .as_str()
        .parse::<u16>()
        .map_err(|_| "Port must be between 1 and 65535".to_owned())?;
    Ok(match kind {
        ConnectionKind::Ssh => ConnectionSettings::Ssh(SshSettings {
            host: form.host.to_string(),
            port,
            username: form.username.to_string(),
            auth_method: match form.auth_method {
                0 => SshAuthMethod::PublicKey {
                    key_ref: cm_core::CredentialRef::new(
                        CredentialId::UNSAVED,
                        cm_core::CredentialPurpose::SshKey,
                    ),
                },
                2 => SshAuthMethod::Agent,
                _ => SshAuthMethod::Password,
            },
        }),
        ConnectionKind::Rdp => {
            let mut pair = form.rdp_resolution.split('x');
            let width = pair
                .next()
                .and_then(|x| x.parse::<u16>().ok())
                .unwrap_or(RdpSettings::DEFAULT_WIDTH);
            let height = pair
                .next()
                .and_then(|x| x.parse::<u16>().ok())
                .unwrap_or(RdpSettings::DEFAULT_HEIGHT);
            if pair.next().is_some() {
                return Err("Resolution must be WIDTHxHEIGHT".into());
            }
            ConnectionSettings::Rdp(RdpSettings {
                host: form.host.to_string(),
                port,
                domain: if form.rdp_domain.trim().is_empty() {
                    None
                } else {
                    Some(form.rdp_domain.trim().to_owned())
                },
                username: if form.username.trim().is_empty() {
                    None
                } else {
                    Some(form.username.trim().to_owned())
                },
                width,
                height,
                color_depth: 32,
            })
        }
        ConnectionKind::Telnet => ConnectionSettings::Telnet(TelnetSettings {
            host: form.host.trim().to_owned(),
            port,
        }),
        ConnectionKind::LocalTerminal => ConnectionSettings::Local(LocalSettings::default()),
    })
}

fn wire_new_group(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_new_group(move |raw| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(parent) = crate::domain_ui_id::parse_optional_group_id(raw.as_str()) else {
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let idx = group_index(parent, &ws.groups);
        ui.set_group_form(GroupForm {
            id: SharedString::default(),
            name: "New Group".into(),
            parent_id: parent
                .map(crate::domain_ui_id::group_id_text)
                .unwrap_or_default(),
            default_cred_idx: 0,
            selected_parent_idx: idx,
        });
        begin_editor(&state, &ui, super::state::EditorKind::Group);
        ui.set_group_editor_open(true);
    });
}
fn wire_edit_group(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_edit_group(move |raw| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(id) = crate::domain_ui_id::parse_group_id(raw.as_str()) else {
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let Some(g) = ws.groups.iter().find(|g| g.id == id) else {
            return;
        };
        ui.set_group_form(GroupForm {
            id: crate::domain_ui_id::group_id_text(g.id),
            name: g.name.clone().into(),
            parent_id: g
                .parent_id
                .map(crate::domain_ui_id::group_id_text)
                .unwrap_or_default(),
            default_cred_idx: credential_index(
                g.default_credential,
                &ws.credentials,
                &ws.credential_folders,
            ),
            selected_parent_idx: group_index(g.parent_id, &ws.groups),
        });
        begin_editor(&state, &ui, super::state::EditorKind::Group);
        ui.set_group_editor_open(true);
    });
}
fn wire_group_save(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_group_save(move || {
        let Some(ui) = weak.upgrade() else { return };
        let form = ui.get_group_form();
        let Ok(id) = crate::domain_ui_id::parse_group_form_id(form.id.as_str()) else {
            super::push_toast(&ui, &state, "Invalid group ID.");
            return;
        };
        let Ok(_) = crate::domain_ui_id::parse_optional_group_id(form.parent_id.as_str()) else {
            super::push_toast(&ui, &state, "Invalid parent group ID.");
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let parent = group_at_index(form.selected_parent_idx, &ws.groups);
        if form.selected_parent_idx > 0 && parent.is_none() {
            super::push_toast(&ui, &state, "The selected parent no longer exists.");
            return;
        }
        if id != GroupId::UNSAVED && parent.is_some_and(|p| would_cycle(id, p, &ws.groups)) {
            super::push_toast(
                &ui,
                &state,
                "A group cannot be moved into itself or a descendant.",
            );
            return;
        }
        let sort = next_sort(
            ws.groups
                .iter()
                .filter(|g| g.parent_id == parent && g.id != id),
            |g| g.sort,
        )
        .unwrap_or(0);
        let value = Group {
            id,
            parent_id: parent,
            name: form.name.to_string(),
            sort,
            default_credential: credential_at_index(
                form.default_cred_idx,
                &ws.credentials,
                &ws.credential_folders,
            ),
        };
        submit_editor_mutation(
            &ui,
            &state,
            WorkspaceMutation::UpsertGroup { value },
            editor_ticket(&state, super::state::EditorKind::Group),
        );
    });
}
fn would_cycle(id: GroupId, mut parent: GroupId, groups: &[Group]) -> bool {
    for _ in 0..=groups.len() {
        if parent == id {
            return true;
        }
        let Some(group) = groups.iter().find(|g| g.id == parent) else {
            return false;
        };
        let Some(next) = group.parent_id else {
            return false;
        };
        parent = next;
    }
    true
}

fn wire_new_credential(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_new_cred(move |raw| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(folder) = crate::domain_ui_id::parse_optional_credential_folder_id(raw.as_str())
        else {
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        ui.set_cred_form(CredFormData {
            id: SharedString::default(),
            name: "New Credential".into(),
            kind: 0,
            username: SharedString::default(),
            folder_id: folder
                .map(crate::domain_ui_id::credential_folder_id_text)
                .unwrap_or_default(),
            selected_folder_idx: folder_index(folder, &ws.credential_folders),
            secret: SharedString::default(),
            passphrase: SharedString::default(),
        });
        begin_editor(&state, &ui, super::state::EditorKind::Credential);
        ui.set_cred_editor_open(true);
    });
}

fn eligible_folder_parents(
    editing: Option<CredentialFolderId>,
    folders: &[CredentialFolder],
) -> Vec<Option<CredentialFolderId>> {
    let mut excluded = std::collections::HashSet::new();
    if let Some(id) = editing {
        excluded.insert(id);
        loop {
            let before = excluded.len();
            let children: Vec<_> = folders
                .iter()
                .filter(|f| f.parent_id.is_some_and(|p| excluded.contains(&p)))
                .map(|f| f.id)
                .collect();
            excluded.extend(children);
            if excluded.len() == before {
                break;
            }
        }
    }
    let mut sorted: Vec<&CredentialFolder> = folders
        .iter()
        .filter(|f| !excluded.contains(&f.id))
        .collect();
    sorted.sort_by_key(|f| (f.sort, f.id.get()));
    let mut result = vec![None];
    result.extend(sorted.into_iter().map(|f| Some(f.id)));
    result
}

fn wire_new_credential_folder(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_new_cred_folder(move |raw_parent| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(parent) =
            crate::domain_ui_id::parse_optional_credential_folder_id(raw_parent.as_str())
        else {
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let choices = eligible_folder_parents(None, &ws.credential_folders);
        let names = folder_parent_names(&choices, &ws.credential_folders);
        ui.set_cred_folder_parent_name_list(ModelRc::from(Rc::new(VecModel::from(names))));
        ui.set_cred_folder_form(crate::generated_ui::CredFolderFormData {
            id: "".into(),
            name: "New Folder".into(),
            parent_id: parent
                .map(crate::domain_ui_id::credential_folder_id_text)
                .unwrap_or_default(),
            selected_parent_idx: choices.iter().position(|p| *p == parent).unwrap_or(0) as i32,
        });
        begin_editor(&state, &ui, super::state::EditorKind::CredentialFolder);
        ui.set_cred_folder_editor_open(true);
    });
}

fn wire_edit_credential_folder(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_edit_cred_folder(move |raw| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(id) = crate::domain_ui_id::parse_credential_folder_id(raw.as_str()) else {
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let Some(folder) = ws.credential_folders.iter().find(|f| f.id == id) else {
            return;
        };
        let choices = eligible_folder_parents(Some(id), &ws.credential_folders);
        let names = folder_parent_names(&choices, &ws.credential_folders);
        ui.set_cred_folder_parent_name_list(ModelRc::from(Rc::new(VecModel::from(names))));
        ui.set_cred_folder_form(crate::generated_ui::CredFolderFormData {
            id: crate::domain_ui_id::credential_folder_id_text(id),
            name: folder.name.clone().into(),
            parent_id: folder
                .parent_id
                .map(crate::domain_ui_id::credential_folder_id_text)
                .unwrap_or_default(),
            selected_parent_idx: choices
                .iter()
                .position(|p| *p == folder.parent_id)
                .unwrap_or(0) as i32,
        });
        begin_editor(&state, &ui, super::state::EditorKind::CredentialFolder);
        ui.set_cred_folder_editor_open(true);
    });
}

fn folder_parent_names(
    choices: &[Option<CredentialFolderId>],
    folders: &[CredentialFolder],
) -> Vec<SharedString> {
    choices
        .iter()
        .map(|choice| match choice {
            None => SharedString::from("Root (no folder)"),
            Some(id) => folders
                .iter()
                .find(|f| f.id == *id)
                .map(|f| f.name.clone().into())
                .unwrap_or_default(),
        })
        .collect()
}

fn wire_save_credential_folder(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_cred_folder_save(move || {
        let Some(ui) = weak.upgrade() else { return };
        let form = ui.get_cred_folder_form();
        let Ok(id) = crate::domain_ui_id::parse_credential_folder_form_id(form.id.as_str()) else {
            super::set_editor_error(
                &ui,
                super::state::EditorKind::CredentialFolder,
                "Invalid credential folder ID.",
            );
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let choices = eligible_folder_parents(
            (id != CredentialFolderId::UNSAVED).then_some(id),
            &ws.credential_folders,
        );
        let Some(parent) = usize::try_from(form.selected_parent_idx)
            .ok()
            .and_then(|i| choices.get(i))
            .copied()
        else {
            super::set_editor_error(
                &ui,
                super::state::EditorKind::CredentialFolder,
                "Select a valid parent folder.",
            );
            return;
        };
        if id != CredentialFolderId::UNSAVED
            && parent.is_some_and(|p| folder_would_cycle(id, p, &ws.credential_folders))
        {
            super::set_editor_error(
                &ui,
                super::state::EditorKind::CredentialFolder,
                "A folder cannot be moved into itself or a descendant.",
            );
            return;
        }
        let existing = ws.credential_folders.iter().find(|f| f.id == id);
        let sort = if existing.is_some_and(|f| f.parent_id == parent) {
            existing.map(|f| f.sort).unwrap_or(0)
        } else {
            let Some(sort) = next_sort(
                ws.credential_folders
                    .iter()
                    .filter(|f| f.parent_id == parent && f.id != id),
                |f| f.sort,
            ) else {
                super::set_editor_error(
                    &ui,
                    super::state::EditorKind::CredentialFolder,
                    "Folder ordering is exhausted.",
                );
                return;
            };
            sort
        };
        let value = CredentialFolder {
            id,
            parent_id: parent,
            name: form.name.to_string(),
            sort,
        };
        submit_editor_mutation(
            &ui,
            &state,
            WorkspaceMutation::UpsertCredentialFolder { value },
            editor_ticket(&state, super::state::EditorKind::CredentialFolder),
        );
    });
}

fn folder_would_cycle(
    id: CredentialFolderId,
    mut parent: CredentialFolderId,
    folders: &[CredentialFolder],
) -> bool {
    for _ in 0..=folders.len() {
        if parent == id {
            return true;
        }
        let Some(folder) = folders.iter().find(|f| f.id == parent) else {
            return false;
        };
        let Some(next) = folder.parent_id else {
            return false;
        };
        parent = next;
    }
    true
}

fn wire_reorder_conn_group(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_reorder_conn_row(move |raw, direction| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(id) = crate::domain_ui_id::parse_connection_id(raw.as_str()) else {
            return;
        };
        let Some(workspace) = state.borrow().workspace.clone() else {
            return;
        };
        if state.borrow().refresh_required || state.borrow().ordering_plan.is_some() {
            return;
        }
        let Some(current) = workspace.connections.iter().find(|value| value.id == id) else {
            return;
        };
        let mut siblings: Vec<_> = workspace
            .connections
            .iter()
            .filter(|value| value.group_id == current.group_id)
            .collect();
        siblings.sort_by_key(|value| (value.sort, value.id.get()));
        let Some(index) = siblings.iter().position(|value| value.id == id) else {
            return;
        };
        let delta = if direction < 0 { -1isize } else { 1 };
        let Some(target) = index
            .checked_add_signed(delta)
            .filter(|target| *target < siblings.len())
        else {
            return;
        };
        let mut ordered: Vec<_> = siblings.iter().map(|value| value.id).collect();
        ordered.swap(index, target);
        let mut changes = Vec::new();
        for (position, moved_id) in ordered.iter().enumerate() {
            let Ok(sort) = i64::try_from(position) else {
                return;
            };
            let old = siblings
                .iter()
                .find(|value| value.id == *moved_id)
                .expect("ordered sibling exists");
            if old.sort != sort {
                changes.push(super::state::OrderedMove::Connection {
                    id: old.id,
                    group_id: old.group_id,
                    sort,
                });
            }
        }
        begin_order_plan(&ui, &state, super::state::OrderKind::Connections, changes);
    });

    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_reorder_group_row(move |raw, direction| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(id) = crate::domain_ui_id::parse_group_id(raw.as_str()) else {
            return;
        };
        let Some(workspace) = state.borrow().workspace.clone() else {
            return;
        };
        if state.borrow().refresh_required || state.borrow().ordering_plan.is_some() {
            return;
        }
        let Some(current) = workspace.groups.iter().find(|value| value.id == id) else {
            return;
        };
        let mut siblings: Vec<_> = workspace
            .groups
            .iter()
            .filter(|value| value.parent_id == current.parent_id)
            .collect();
        siblings.sort_by_key(|value| (value.sort, value.id.get()));
        let Some(index) = siblings.iter().position(|value| value.id == id) else {
            return;
        };
        let delta = if direction < 0 { -1isize } else { 1 };
        let Some(target) = index
            .checked_add_signed(delta)
            .filter(|target| *target < siblings.len())
        else {
            return;
        };
        let mut ordered: Vec<_> = siblings.iter().map(|value| value.id).collect();
        ordered.swap(index, target);
        let mut changes = Vec::new();
        for (position, moved_id) in ordered.iter().enumerate() {
            let Ok(sort) = i64::try_from(position) else {
                return;
            };
            let old = siblings
                .iter()
                .find(|value| value.id == *moved_id)
                .expect("ordered sibling exists");
            if old.sort != sort {
                changes.push(super::state::OrderedMove::Group {
                    id: old.id,
                    parent_id: old.parent_id,
                    sort,
                });
            }
        }
        begin_order_plan(&ui, &state, super::state::OrderKind::Groups, changes);
    });
}

fn wire_reorder_credential_folder(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_reorder_cred_folder(move |raw, direction| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(id) = crate::domain_ui_id::parse_credential_folder_id(raw.as_str()) else {
            return;
        };
        let Some(workspace) = state.borrow().workspace.clone() else {
            return;
        };
        if state.borrow().refresh_required || state.borrow().ordering_plan.is_some() {
            return;
        }
        let Some(current) = workspace
            .credential_folders
            .iter()
            .find(|value| value.id == id)
        else {
            return;
        };
        let mut siblings: Vec<_> = workspace
            .credential_folders
            .iter()
            .filter(|value| value.parent_id == current.parent_id)
            .collect();
        siblings.sort_by_key(|value| (value.sort, value.id.get()));
        let Some(index) = siblings.iter().position(|value| value.id == id) else {
            return;
        };
        let delta = if direction < 0 { -1isize } else { 1 };
        let Some(target) = index
            .checked_add_signed(delta)
            .filter(|target| *target < siblings.len())
        else {
            return;
        };
        let mut ordered: Vec<_> = siblings.iter().map(|value| value.id).collect();
        ordered.swap(index, target);
        let mut changes = Vec::new();
        for (position, moved_id) in ordered.iter().enumerate() {
            let Ok(sort) = i64::try_from(position) else {
                return;
            };
            let old = siblings
                .iter()
                .find(|value| value.id == *moved_id)
                .expect("ordered sibling exists");
            if old.sort != sort {
                changes.push(super::state::OrderedMove::CredentialFolder {
                    id: old.id,
                    parent_id: old.parent_id,
                    sort,
                });
            }
        }
        begin_order_plan(
            &ui,
            &state,
            super::state::OrderKind::CredentialFolders,
            changes,
        );
    });
}

fn begin_order_plan(
    ui: &crate::AppWindow,
    shared: &SharedUiState,
    kind: super::state::OrderKind,
    changes: Vec<super::state::OrderedMove>,
) {
    if changes.is_empty() {
        return;
    }
    let (generation, revision) = {
        let mut state = shared.borrow_mut();
        if state.refresh_required || state.ordering_plan.is_some() {
            return;
        }
        state.next_order_plan_generation = state.next_order_plan_generation.wrapping_add(1).max(1);
        let generation = state.next_order_plan_generation;
        state.ordering_plan = Some(super::state::WorkspaceReorderPlan {
            generation,
            kind,
            changes,
            next_index: 0,
        });
        (generation, state.revision)
    };
    if kind == super::state::OrderKind::CredentialFolders {
        ui.set_cred_folder_reorder_pending(true);
    }
    let Some(revision) = revision else {
        stop_order_plan(ui, shared);
        return;
    };
    submit_next_order_plan_step(ui, shared, generation, revision);
}

pub(super) fn submit_next_order_plan_step(
    ui: &crate::AppWindow,
    shared: &SharedUiState,
    generation: u64,
    revision: cm_core::application::WorkspaceRevision,
) {
    let next = {
        let state = shared.borrow();
        let Some(plan) = state
            .ordering_plan
            .as_ref()
            .filter(|plan| plan.generation == generation)
        else {
            return;
        };
        plan.changes
            .get(plan.next_index)
            .copied()
            .map(|change| (plan.next_index, change))
    };
    let Some((step_index, change)) = next else {
        stop_order_plan(ui, shared);
        return;
    };
    let accepted = super::submit(
        ui,
        shared,
        AppCommand::Mutate {
            meta: MutationMeta {
                expected_revision: revision,
            },
            operation: change.into_mutation(),
        },
        PendingUiAction::MoveOrderedItem {
            plan_generation: generation,
            step_index,
        },
    );
    if accepted.is_none() {
        stop_order_plan(ui, shared);
    }
}

pub(super) fn stop_order_plan(ui: &crate::AppWindow, shared: &SharedUiState) {
    let plan = shared.borrow_mut().ordering_plan.take();
    if plan.is_some_and(|plan| plan.kind == super::state::OrderKind::CredentialFolders) {
        ui.set_cred_folder_reorder_pending(false);
    }
    super::events::require_refresh(ui, shared);
    super::events::submit_refresh(ui, shared);
}
fn wire_edit_credential(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_edit_cred(move |raw| {
        let Some(ui) = weak.upgrade() else { return };
        let Ok(id) = crate::domain_ui_id::parse_credential_id(raw.as_str()) else {
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let Some(c) = ws.credentials.iter().find(|c| c.id == id) else {
            return;
        };
        ui.set_cred_form(CredFormData {
            id: crate::domain_ui_id::credential_id_text(c.id),
            name: c.name.clone().into(),
            kind: match c.kind {
                CredentialKind::Password => 0,
                CredentialKind::SshKey => 1,
                CredentialKind::SshKeyWithPassphrase => 2,
            },
            username: c.username.clone().unwrap_or_default().into(),
            folder_id: c
                .folder_id
                .map(crate::domain_ui_id::credential_folder_id_text)
                .unwrap_or_default(),
            selected_folder_idx: folder_index(c.folder_id, &ws.credential_folders),
            secret: SharedString::default(),
            passphrase: SharedString::default(),
        });
        begin_editor(&state, &ui, super::state::EditorKind::Credential);
        ui.set_cred_editor_open(true);
    });
}
fn wire_credential_save(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_cred_save(move || {
        let Some(ui) = weak.upgrade() else { return };
        let form = ui.get_cred_form();
        let Ok(id) = crate::domain_ui_id::parse_credential_form_id(form.id.as_str()) else {
            super::push_toast(&ui, &state, "Invalid credential ID.");
            return;
        };
        let Ok(_) =
            crate::domain_ui_id::parse_optional_credential_folder_id(form.folder_id.as_str())
        else {
            super::push_toast(&ui, &state, "Invalid credential folder ID.");
            return;
        };
        let Some(ws) = state.borrow().workspace.clone() else {
            return;
        };
        let folder = folder_at_index(form.selected_folder_idx, &ws.credential_folders);
        if form.selected_folder_idx > 0 && folder.is_none() {
            super::push_toast(&ui, &state, "The selected folder no longer exists.");
            return;
        }
        let kind = match form.kind {
            1 => CredentialKind::SshKey,
            2 => CredentialKind::SshKeyWithPassphrase,
            _ => CredentialKind::Password,
        };
        let value = Credential {
            id,
            name: form.name.to_string(),
            kind,
            folder_id: folder,
            username: if form.username.trim().is_empty() {
                None
            } else {
                Some(form.username.trim().to_string())
            },
        };
        let secret = form.secret.to_string();
        let passphrase = form.passphrase.to_string();
        let mut clear_form = form.clone();
        clear_form.secret = SharedString::default();
        clear_form.passphrase = SharedString::default();
        let change = |v: String| {
            if v.is_empty() {
                SecretChange::Keep
            } else {
                SecretChange::Replace(cm_core::Secret::from_string(v))
            }
        };
        let (password, ssh_key, ssh_passphrase) = match kind {
            CredentialKind::Password => (change(secret), SecretChange::Clear, SecretChange::Clear),
            CredentialKind::SshKey => (SecretChange::Clear, change(secret), SecretChange::Clear),
            CredentialKind::SshKeyWithPassphrase => {
                (SecretChange::Clear, change(secret), change(passphrase))
            }
        };
        if submit_editor_mutation(
            &ui,
            &state,
            WorkspaceMutation::UpsertCredential {
                value,
                secret_intent: CredentialSecretIntent {
                    password,
                    ssh_key,
                    ssh_passphrase,
                },
            },
            editor_ticket(&state, super::state::EditorKind::Credential),
        )
        .is_some()
        {
            ui.set_cred_form(clear_form);
        }
    });
}

fn wire_delete_connection(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_delete_conn_row(move |raw, is_group| {
        let Some(ui) = weak.upgrade() else { return };
        if is_group {
            let Ok(id) = crate::domain_ui_id::parse_group_id(raw.as_str()) else {
                return;
            };
            submit_mutation(&ui, &state, WorkspaceMutation::DeleteGroup { id });
        } else {
            let Ok(id) = crate::domain_ui_id::parse_connection_id(raw.as_str()) else {
                return;
            };
            submit_mutation(&ui, &state, WorkspaceMutation::DeleteConnection { id });
        }
    });
}
fn wire_delete_credential(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_delete_cred_row(move |raw, is_folder| {
        let Some(ui) = weak.upgrade() else { return };
        if is_folder {
            let Ok(id) = crate::domain_ui_id::parse_credential_folder_id(raw.as_str()) else {
                return;
            };
            submit_mutation(
                &ui,
                &state,
                WorkspaceMutation::DeleteCredentialFolder { id },
            );
        } else {
            let Ok(id) = crate::domain_ui_id::parse_credential_id(raw.as_str()) else {
                return;
            };
            submit_mutation(&ui, &state, WorkspaceMutation::DeleteCredential { id });
        }
    });
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(super) fn wire_refresh(ui: &crate::AppWindow, shared: &SharedUiState) {
    let weak = ui.as_weak();
    let state = shared.clone();
    ui.on_retry_workspace_refresh(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_workspace_load_error("".into());
            ui.set_workspace_refresh_pending(true);
            if super::submit(
                &ui,
                &state,
                cm_core::application::AppCommand::ListWorkspace,
                PendingUiAction::RefreshWorkspace,
            )
            .is_none()
            {
                ui.set_workspace_refresh_pending(false);
            }
        }
    });
}

pub(super) fn submit_mutation(
    ui: &crate::AppWindow,
    state: &SharedUiState,
    operation: WorkspaceMutation,
) {
    submit_editor_mutation(ui, state, operation, None);
}

fn submit_editor_mutation(
    ui: &crate::AppWindow,
    state: &SharedUiState,
    operation: WorkspaceMutation,
    editor: Option<super::state::EditorCorrelation>,
) -> Option<cm_core::application::RequestId> {
    let (revision, blocked) = {
        let current = state.borrow();
        (current.revision, current.refresh_required)
    };
    if blocked {
        super::push_toast(ui, state, "Refresh the workspace before saving changes.");
        return None;
    }
    let Some(revision) = revision else {
        super::push_toast(ui, state, "The workspace is still loading.");
        return None;
    };
    if state.borrow().ordering_plan.is_some() {
        super::push_toast(ui, state, "Wait for credential folder ordering to finish.");
        return None;
    }
    super::submit(
        ui,
        state,
        cm_core::application::AppCommand::Mutate {
            meta: cm_core::application::MutationMeta {
                expected_revision: revision,
            },
            operation,
        },
        PendingUiAction::Mutation { editor },
    )
}

#[allow(dead_code)]
fn _shared_names_model(items: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::from(Rc::new(VecModel::from(
        items
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    )))
}
