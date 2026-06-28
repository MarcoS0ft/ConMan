//! Connection and group tree flattening for the Connections side panel.
//!
//! [`ConnectionTree`] maintains the full list of groups and connections loaded
//! from the repository plus the expand/collapse state per group.
//! [`ConnectionTree::flat`] produces the [`ConnRow`] list the Slint `ListView`
//! consumes; the Rust controller calls this after every mutation and pushes the
//! result into the model.
//!
//! The tree is bounded by [`MAX_DEPTH`] against pathological (or corrupt)
//! circular parent chains.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionRepository, ConnectionSettings, Credential,
    CredentialId, Group, GroupId, RepositoryError, SshAuthMethod,
};
use slint::SharedString;

use crate::ConnRow;

/// Maximum recursion depth when flattening (guards against cycles in a
/// corrupt tree; a valid N-node tree has paths of at most N steps).
const MAX_DEPTH: usize = 64;

/// Returns the current Unix epoch in seconds (used for `created_at` /
/// `updated_at` on newly created entities). Falls back to 0 on error.
pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// ConnectionTree
// ---------------------------------------------------------------------------

/// Maintains connection + group state for the Connections panel.
///
/// Call [`flat`][ConnectionTree::flat] to get the ordered, visible row list
/// honouring current expand/collapse state.
#[derive(Debug)]
pub struct ConnectionTree {
    pub(crate) groups: Vec<Group>,
    pub(crate) connections: Vec<Connection>,
    /// Group IDs that are currently expanded.
    pub(crate) expanded: HashSet<i64>,
    /// The currently selected connection id (not group).
    pub(crate) selected_conn_id: Option<i64>,
}

impl ConnectionTree {
    /// Load from the repository (lists all groups and connections once).
    pub fn load(repo: &dyn ConnectionRepository) -> Result<Self, RepositoryError> {
        let groups = repo.list_groups()?;
        let connections = repo.list_connections()?;
        Ok(Self::new(groups, connections))
    }

    /// Build from pre-fetched lists. Root groups start expanded.
    pub fn new(groups: Vec<Group>, connections: Vec<Connection>) -> Self {
        let expanded: HashSet<i64> = groups
            .iter()
            .filter(|g| g.parent_id.is_none())
            .map(|g| g.id.get())
            .collect();
        Self {
            groups,
            connections,
            expanded,
            selected_conn_id: None,
        }
    }

    /// Reload groups and connections from the repository, preserving
    /// expand/collapse state and selection.
    pub fn reload(&mut self, repo: &dyn ConnectionRepository) -> Result<(), RepositoryError> {
        let prev_expanded = self.expanded.clone();
        let prev_sel = self.selected_conn_id;
        self.groups = repo.list_groups()?;
        self.connections = repo.list_connections()?;
        self.expanded = prev_expanded;
        self.selected_conn_id = prev_sel;
        Ok(())
    }

    /// Toggle the expanded/collapsed state of a group.
    pub fn toggle_expand(&mut self, group_id: i64) {
        if self.expanded.contains(&group_id) {
            self.expanded.remove(&group_id);
        } else {
            self.expanded.insert(group_id);
        }
    }

    /// Mark a connection as selected (highlights the row).
    pub fn select_conn(&mut self, conn_id: i64) {
        self.selected_conn_id = Some(conn_id);
    }

    /// Returns the flat, ordered list of visible rows respecting expand/collapse.
    pub fn flat(&self) -> Vec<ConnRow> {
        let mut out = Vec::new();

        // Root-level groups (parent_id == None).
        let mut root_groups: Vec<&Group> = self
            .groups
            .iter()
            .filter(|g| g.parent_id.is_none())
            .collect();
        root_groups.sort_by_key(|g| (g.sort, g.id.get()));

        for group in root_groups {
            self.push_group(group, 0, &mut out);
        }

        // Root-level connections (group_id == None).
        let mut root_conns: Vec<&Connection> = self
            .connections
            .iter()
            .filter(|c| c.group_id.is_none())
            .collect();
        root_conns.sort_by_key(|c| (c.sort, c.id.get()));

        for conn in root_conns {
            out.push(self.make_conn_row(conn, 0));
        }

        out
    }

    fn push_group(&self, group: &Group, depth: usize, out: &mut Vec<ConnRow>) {
        if depth >= MAX_DEPTH {
            return;
        }
        let expanded = self.expanded.contains(&group.id.get());
        out.push(ConnRow {
            id: group.id.get() as i32,
            label: SharedString::from(group.name.as_str()),
            host: SharedString::from(""),
            kind: SharedString::from(""),
            status: SharedString::from(""),
            is_group: true,
            expanded,
            selected: false,
            depth: depth as i32,
        });

        if !expanded {
            return;
        }

        // Sub-groups of this group.
        let mut sub_groups: Vec<&Group> = self
            .groups
            .iter()
            .filter(|g| g.parent_id == Some(group.id))
            .collect();
        sub_groups.sort_by_key(|g| (g.sort, g.id.get()));
        for sg in sub_groups {
            self.push_group(sg, depth + 1, out);
        }

        // Connections in this group.
        let mut group_conns: Vec<&Connection> = self
            .connections
            .iter()
            .filter(|c| c.group_id == Some(group.id))
            .collect();
        group_conns.sort_by_key(|c| (c.sort, c.id.get()));
        for conn in group_conns {
            out.push(self.make_conn_row(conn, depth + 1));
        }
    }

    fn make_conn_row(&self, conn: &Connection, depth: usize) -> ConnRow {
        let selected = self.selected_conn_id == Some(conn.id.get());
        let (host, kind_str) = conn_host_kind(&conn.settings);
        ConnRow {
            id: conn.id.get() as i32,
            label: SharedString::from(conn.name.as_str()),
            host: SharedString::from(host.as_str()),
            kind: SharedString::from(kind_str),
            status: SharedString::from("disconnected"),
            is_group: false,
            expanded: false,
            selected,
            depth: depth as i32,
        }
    }

    // -----------------------------------------------------------------------
    // Row-lookup helpers used by the controller
    // -----------------------------------------------------------------------

    /// The group_id encoded in a flat row (group rows carry the group id;
    /// connection rows carry the group_id of the connection).
    pub fn group_id_at_flat_idx(&self, flat_idx: usize) -> Option<i64> {
        let flat = self.flat();
        let row = flat.get(flat_idx)?;
        if row.is_group {
            Some(row.id as i64)
        } else {
            self.connections
                .iter()
                .find(|c| c.id.get() == row.id as i64)
                .and_then(|c| c.group_id.map(|g| g.get()))
        }
    }

    pub fn group_id_at_flat_row(&self, flat_idx: usize) -> Option<GroupId> {
        self.group_id_at_flat_idx(flat_idx).map(GroupId::new)
    }

    /// The row id and is_group flag at a flat index.
    pub fn row_at_flat_idx(&self, flat_idx: usize) -> Option<(i32, bool)> {
        let flat = self.flat();
        flat.get(flat_idx).map(|r| (r.id, r.is_group))
    }

    /// Look up a group by id.
    pub fn group_by_id(&self, id: i64) -> Option<&Group> {
        self.groups.iter().find(|g| g.id.get() == id)
    }

    /// Look up a connection by id.
    pub fn conn_by_id(&self, id: i64) -> Option<&Connection> {
        self.connections.iter().find(|c| c.id.get() == id)
    }

    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    pub fn connections(&self) -> &[Connection] {
        &self.connections
    }

    /// Next sort value for a new sibling at root or inside `parent_id`.
    pub fn next_sort_in_group(&self, parent_id: Option<GroupId>) -> i64 {
        self.connections
            .iter()
            .filter(|c| c.group_id == parent_id)
            .map(|c| c.sort)
            .chain(
                self.groups
                    .iter()
                    .filter(|g| g.parent_id == parent_id)
                    .map(|g| g.sort),
            )
            .max()
            .map(|m| m + 1)
            .unwrap_or(0)
    }

    pub fn next_group_sort_in_parent(&self, parent_id: Option<GroupId>) -> i64 {
        self.groups
            .iter()
            .filter(|g| g.parent_id == parent_id)
            .map(|g| g.sort)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0)
    }
}

/// Derives the display host string and protocol chip label from settings.
pub fn conn_host_kind(settings: &ConnectionSettings) -> (String, &'static str) {
    match settings {
        ConnectionSettings::Ssh(s) => (format!("{}@{}:{}", s.username, s.host, s.port), "SSH"),
        ConnectionSettings::Rdp(s) => {
            let user = s.username.as_deref().unwrap_or("");
            (format!("{}@{}:{}", user, s.host, s.port), "RDP")
        }
        ConnectionSettings::Local(_) => (String::new(), "LOCAL"),
    }
}

/// Build a default connection for a new SSH connection.
pub fn new_ssh_connection(name: &str, group_id: Option<GroupId>, sort: i64) -> Connection {
    use cm_core::SshSettings;
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_owned(),
        ConnectionKind::Ssh,
        ConnectionSettings::Ssh(SshSettings {
            host: String::new(),
            port: SshSettings::DEFAULT_PORT,
            username: String::new(),
            auth_method: SshAuthMethod::Password,
        }),
        None,
        sort,
        now_secs(),
        now_secs(),
    )
    // SAFETY: SshSettings always matches ConnectionKind::Ssh.
    .expect("default SSH connection is always valid")
}

/// Build a default local connection.
pub fn new_local_connection(name: &str, group_id: Option<GroupId>, sort: i64) -> Connection {
    use cm_core::LocalSettings;
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_owned(),
        ConnectionKind::LocalTerminal,
        ConnectionSettings::Local(LocalSettings::default()),
        None,
        sort,
        now_secs(),
        now_secs(),
    )
    .expect("default local connection is always valid")
}

// ---------------------------------------------------------------------------
// Credential name list helper
// ---------------------------------------------------------------------------

/// Build the flat credential name list for all dropdowns.
///
/// Index 0 is always the "inherit" sentinel; subsequent entries are
/// `"<folder>/<name>"` paths (or just `"<name>"` for root credentials).
pub fn build_cred_name_list(
    credentials: &[Credential],
    folders: &[cm_core::CredentialFolder],
    inherit_label: &str,
) -> Vec<SharedString> {
    let mut out = vec![SharedString::from(inherit_label)];
    // Root credentials first (no folder).
    let mut root_creds: Vec<&Credential> = credentials
        .iter()
        .filter(|c| c.folder_id.is_none())
        .collect();
    root_creds.sort_by_key(|c| &c.name);
    for c in root_creds {
        out.push(SharedString::from(c.name.as_str()));
    }
    // Credentials inside folders, using a simple folder-name prefix.
    for folder in folders {
        let folder_name = &folder.name;
        let mut folder_creds: Vec<&Credential> = credentials
            .iter()
            .filter(|c| c.folder_id == Some(folder.id))
            .collect();
        folder_creds.sort_by_key(|c| &c.name);
        for c in folder_creds {
            out.push(SharedString::from(
                format!("{}/{}", folder_name, c.name).as_str(),
            ));
        }
    }
    out
}

/// Find the `selected-cred-idx` for a given `CredentialId` in the flat list.
///
/// Returns 0 (inherit sentinel) when `cred_id` is `None` or not found.
pub fn cred_name_idx(
    cred_id: Option<CredentialId>,
    credentials: &[Credential],
    folders: &[cm_core::CredentialFolder],
) -> i32 {
    let Some(id) = cred_id else { return 0 };
    let list = build_cred_name_list(credentials, folders, "");
    // list[0] is the sentinel; skip it.
    for (i, cred) in credentials.iter().enumerate() {
        if cred.id == id {
            // i is 0-based into `credentials`; offset +1 for the sentinel.
            let _ = list; // silence unused; the loop below is the real lookup.
            let _ = i;
        }
    }
    // Recompute the index by looking for the credential name in the list.
    let Some(cred) = credentials.iter().find(|c| c.id == id) else {
        return 0;
    };
    let name = if let Some(fid) = cred.folder_id {
        let folder_name = folders
            .iter()
            .find(|f| f.id == fid)
            .map(|f| f.name.as_str())
            .unwrap_or("");
        format!("{}/{}", folder_name, cred.name)
    } else {
        cred.name.clone()
    };
    let full_list = build_cred_name_list(credentials, folders, "");
    full_list
        .iter()
        .position(|s| s.as_str() == name.as_str())
        .map(|i| i as i32)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::{ConnectionSettings, LocalSettings, SshSettings};

    fn make_group(id: i64, parent_id: Option<i64>, name: &str, sort: i64) -> Group {
        Group {
            id: GroupId::new(id),
            parent_id: parent_id.map(GroupId::new),
            name: name.to_owned(),
            sort,
            default_credential: None,
        }
    }

    fn make_ssh(id: i64, group_id: Option<i64>, name: &str, sort: i64) -> Connection {
        Connection::new(
            ConnectionId::new(id),
            group_id.map(GroupId::new),
            name.to_owned(),
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(SshSettings {
                host: "10.0.0.1".to_owned(),
                port: 22,
                username: "ops".to_owned(),
                auth_method: SshAuthMethod::Password,
            }),
            None,
            sort,
            0,
            0,
        )
        .unwrap()
    }

    fn make_local(id: i64, group_id: Option<i64>, name: &str, sort: i64) -> Connection {
        Connection::new(
            ConnectionId::new(id),
            group_id.map(GroupId::new),
            name.to_owned(),
            ConnectionKind::LocalTerminal,
            ConnectionSettings::Local(LocalSettings::default()),
            None,
            sort,
            0,
            0,
        )
        .unwrap()
    }

    // ── flatten tests ────────────────────────────────────────────────────

    #[test]
    fn flat_empty_tree() {
        let tree = ConnectionTree::new(vec![], vec![]);
        assert_eq!(tree.flat().len(), 0);
    }

    #[test]
    fn flat_single_group_with_connections_expanded() {
        let groups = vec![make_group(1, None, "Lab", 0)];
        let conns = vec![
            make_ssh(10, Some(1), "web-01", 0),
            make_ssh(11, Some(1), "db-01", 1),
        ];
        let tree = ConnectionTree::new(groups, conns);
        let flat = tree.flat();
        assert_eq!(flat.len(), 3);
        assert!(flat[0].is_group);
        assert_eq!(flat[0].label.as_str(), "Lab");
        assert_eq!(flat[0].depth, 0);
        assert!(!flat[1].is_group);
        assert_eq!(flat[1].depth, 1);
        assert_eq!(flat[2].depth, 1);
    }

    #[test]
    fn flat_subgroup_depth() {
        let groups = vec![
            make_group(1, None, "Lab", 0),
            make_group(2, Some(1), "Prod", 0),
        ];
        let conns = vec![
            make_ssh(10, Some(1), "web-01", 0),
            make_ssh(20, Some(2), "db-prod", 0),
        ];
        let mut tree = ConnectionTree::new(groups, conns);
        tree.expanded.insert(2); // expand Prod
        let flat = tree.flat();
        // Lab(0), Prod(1), db-prod(2), web-01(1)
        assert_eq!(flat.len(), 4);
        assert_eq!(flat[0].label.as_str(), "Lab");
        assert_eq!(flat[0].depth, 0);
        assert_eq!(flat[1].label.as_str(), "Prod");
        assert_eq!(flat[1].depth, 1);
        assert_eq!(flat[2].label.as_str(), "db-prod");
        assert_eq!(flat[2].depth, 2);
        assert_eq!(flat[3].label.as_str(), "web-01");
        assert_eq!(flat[3].depth, 1);
    }

    #[test]
    fn toggle_expand_hides_children() {
        let groups = vec![make_group(1, None, "Lab", 0)];
        let conns = vec![make_ssh(10, Some(1), "web-01", 0)];
        let mut tree = ConnectionTree::new(groups, conns);
        assert_eq!(tree.flat().len(), 2);

        tree.toggle_expand(1);
        assert_eq!(tree.flat().len(), 1);

        tree.toggle_expand(1);
        assert_eq!(tree.flat().len(), 2);
    }

    #[test]
    fn selected_connection_marked() {
        let groups = vec![make_group(1, None, "Lab", 0)];
        let conns = vec![make_ssh(10, Some(1), "web-01", 0)];
        let mut tree = ConnectionTree::new(groups, conns);
        tree.select_conn(10);
        let flat = tree.flat();
        assert!(!flat[0].selected); // group
        assert!(flat[1].selected); // connection
    }

    #[test]
    fn groups_rendered_before_same_level_connections() {
        // Within the same parent, sub-groups are listed before connections.
        let groups = vec![make_group(1, None, "A", 0), make_group(2, Some(1), "B", 0)];
        let conns = vec![
            make_ssh(10, Some(1), "leaf-of-A", 0),
            make_ssh(20, Some(2), "leaf-of-B", 0),
        ];
        let mut tree = ConnectionTree::new(groups, conns);
        tree.expanded.insert(2);
        let flat = tree.flat();
        let labels: Vec<&str> = flat.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, ["A", "B", "leaf-of-B", "leaf-of-A"]);
    }

    #[test]
    fn profile_form_kind_local_conn() {
        let conn = make_local(1, None, "shell", 0);
        let (host, kind) = conn_host_kind(&conn.settings);
        assert_eq!(kind, "LOCAL");
        assert_eq!(host, "");
    }

    #[test]
    fn profile_form_kind_ssh_conn() {
        let conn = make_ssh(1, None, "web", 0);
        let (host, kind) = conn_host_kind(&conn.settings);
        assert_eq!(kind, "SSH");
        assert!(host.contains("ops@"));
    }

    #[test]
    fn next_sort_root_empty() {
        let tree = ConnectionTree::new(vec![], vec![]);
        assert_eq!(tree.next_sort_in_group(None), 0);
    }

    #[test]
    fn next_sort_after_existing() {
        let conns = vec![make_ssh(1, None, "a", 3), make_ssh(2, None, "b", 7)];
        let tree = ConnectionTree::new(vec![], conns);
        assert_eq!(tree.next_sort_in_group(None), 8);
    }
}
