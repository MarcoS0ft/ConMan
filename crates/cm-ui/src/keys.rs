//! Credential folder tree flattening for the Keys side panel.
//!
//! [`KeysPanel`] holds the full list of credential folders and credentials and
//! maintains expand/collapse state per folder. [`KeysPanel::flat`] produces the
//! [`CredRow`] list the Slint `ListView` consumes.
//!
//! The tree walk is bounded by [`MAX_DEPTH`] against corrupt or circular trees.

use std::collections::HashSet;

use cm_core::{
    ConnectionRepository, Credential, CredentialFolder, CredentialId, CredentialKind,
    RepositoryError,
};
use slint::SharedString;

use crate::CredRow;

/// Maximum folder-nesting depth (cycle guard).
const MAX_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// KeysPanel
// ---------------------------------------------------------------------------

/// State for the Keys (credentials) side panel.
///
/// Call [`flat`][KeysPanel::flat] to get the ordered, visible row list.
#[derive(Debug)]
pub struct KeysPanel {
    pub(crate) folders: Vec<CredentialFolder>,
    pub(crate) credentials: Vec<Credential>,
    /// Folder IDs that are currently expanded.
    pub(crate) expanded: HashSet<i64>,
    pub(crate) selected_cred_id: Option<i64>,
}

impl KeysPanel {
    /// Load from the repository.
    pub fn load(repo: &dyn ConnectionRepository) -> Result<Self, RepositoryError> {
        let folders = repo.list_credential_folders()?;
        let credentials = repo.list_credentials()?;
        Ok(Self::new(folders, credentials))
    }

    /// Build from pre-fetched lists. Root folders start expanded.
    pub fn new(folders: Vec<CredentialFolder>, credentials: Vec<Credential>) -> Self {
        let expanded: HashSet<i64> = folders
            .iter()
            .filter(|f| f.parent_id.is_none())
            .map(|f| f.id.get())
            .collect();
        Self {
            folders,
            credentials,
            expanded,
            selected_cred_id: None,
        }
    }

    /// Reload from the repository, preserving expand/collapse state and selection.
    pub fn reload(&mut self, repo: &dyn ConnectionRepository) -> Result<(), RepositoryError> {
        let prev_expanded = self.expanded.clone();
        let prev_sel = self.selected_cred_id;
        self.folders = repo.list_credential_folders()?;
        self.credentials = repo.list_credentials()?;
        self.expanded = prev_expanded;
        self.selected_cred_id = prev_sel;
        Ok(())
    }

    /// Toggle the expanded/collapsed state of a folder.
    pub fn toggle_expand(&mut self, folder_id: i64) {
        if self.expanded.contains(&folder_id) {
            self.expanded.remove(&folder_id);
        } else {
            self.expanded.insert(folder_id);
        }
    }

    pub fn select_cred(&mut self, cred_id: i64) {
        self.selected_cred_id = Some(cred_id);
    }

    /// Returns the flat ordered list of visible rows.
    pub fn flat(&self) -> Vec<CredRow> {
        let mut out = Vec::new();

        // Root folders (parent_id == None).
        let mut root_folders: Vec<&CredentialFolder> = self
            .folders
            .iter()
            .filter(|f| f.parent_id.is_none())
            .collect();
        root_folders.sort_by_key(|f| (f.sort, f.id.get()));
        for folder in root_folders {
            self.push_folder(folder, 0, &mut out);
        }

        // Root credentials (folder_id == None).
        let mut root_creds: Vec<&Credential> = self
            .credentials
            .iter()
            .filter(|c| c.folder_id.is_none())
            .collect();
        root_creds.sort_by_key(|c| c.id.get());
        for cred in root_creds {
            out.push(self.make_cred_row(cred, 0));
        }

        out
    }

    fn push_folder(&self, folder: &CredentialFolder, depth: usize, out: &mut Vec<CredRow>) {
        if depth >= MAX_DEPTH {
            return;
        }
        let expanded = self.expanded.contains(&folder.id.get());
        out.push(CredRow {
            id: folder.id.get() as i32,
            label: SharedString::from(folder.name.as_str()),
            kind: SharedString::from(""),
            username: SharedString::from(""),
            is_folder: true,
            expanded,
            selected: false,
            depth: depth as i32,
        });

        if !expanded {
            return;
        }

        // Sub-folders.
        let mut sub_folders: Vec<&CredentialFolder> = self
            .folders
            .iter()
            .filter(|f| f.parent_id == Some(folder.id))
            .collect();
        sub_folders.sort_by_key(|f| (f.sort, f.id.get()));
        for sf in sub_folders {
            self.push_folder(sf, depth + 1, out);
        }

        // Credentials in this folder.
        let mut folder_creds: Vec<&Credential> = self
            .credentials
            .iter()
            .filter(|c| c.folder_id == Some(folder.id))
            .collect();
        folder_creds.sort_by_key(|c| c.id.get());
        for cred in folder_creds {
            out.push(self.make_cred_row(cred, depth + 1));
        }
    }

    fn make_cred_row(&self, cred: &Credential, depth: usize) -> CredRow {
        let selected = self.selected_cred_id == Some(cred.id.get());
        let kind_str = match cred.kind {
            CredentialKind::Password => "Password",
            CredentialKind::SshKey => "SSH Key",
            CredentialKind::SshKeyWithPassphrase => "SSH Key+PP",
        };
        CredRow {
            id: cred.id.get() as i32,
            label: SharedString::from(cred.name.as_str()),
            kind: SharedString::from(kind_str),
            username: SharedString::from(cred.username.as_deref().unwrap_or("")),
            is_folder: false,
            expanded: false,
            selected,
            depth: depth as i32,
        }
    }

    /// Returns a flat list filtered by `query` (case-insensitive substring
    /// match on label, kind, or username). Folders shown only when they or a
    /// descendant matches. When `query` is empty, delegates to [`flat`][Self::flat].
    pub fn flat_filtered(&self, query: &str) -> Vec<CredRow> {
        if query.is_empty() {
            return self.flat();
        }
        let q = query.to_lowercase();
        let matching_cred_ids: std::collections::HashSet<i64> = self
            .credentials
            .iter()
            .filter(|c| {
                let kind_str = match c.kind {
                    CredentialKind::Password => "password",
                    CredentialKind::SshKey => "ssh key",
                    CredentialKind::SshKeyWithPassphrase => "ssh key+pp",
                };
                c.name.to_lowercase().contains(&q)
                    || kind_str.contains(&q)
                    || c.username
                        .as_deref()
                        .map(|u| u.to_lowercase().contains(&q))
                        .unwrap_or(false)
            })
            .map(|c| c.id.get())
            .collect();
        let mut out = Vec::new();
        let mut root_folders: Vec<&CredentialFolder> = self
            .folders
            .iter()
            .filter(|f| f.parent_id.is_none())
            .collect();
        root_folders.sort_by_key(|f| (f.sort, f.id.get()));
        for folder in root_folders {
            self.push_folder_filtered(folder, 0, &q, &matching_cred_ids, &mut out);
        }
        let mut root_creds: Vec<&Credential> = self
            .credentials
            .iter()
            .filter(|c| c.folder_id.is_none())
            .collect();
        root_creds.sort_by_key(|c| c.id.get());
        for cred in root_creds {
            if matching_cred_ids.contains(&cred.id.get()) {
                out.push(self.make_cred_row(cred, 0));
            }
        }
        out
    }

    fn folder_has_match(
        &self,
        folder: &CredentialFolder,
        q: &str,
        matching_cred_ids: &std::collections::HashSet<i64>,
        depth: usize,
    ) -> bool {
        if depth >= MAX_DEPTH {
            return false;
        }
        if folder.name.to_lowercase().contains(q) {
            return true;
        }
        if self
            .credentials
            .iter()
            .filter(|c| c.folder_id == Some(folder.id))
            .any(|c| matching_cred_ids.contains(&c.id.get()))
        {
            return true;
        }
        self.folders
            .iter()
            .filter(|f| f.parent_id == Some(folder.id))
            .any(|sf| self.folder_has_match(sf, q, matching_cred_ids, depth + 1))
    }

    fn push_folder_filtered(
        &self,
        folder: &CredentialFolder,
        depth: usize,
        q: &str,
        matching_cred_ids: &std::collections::HashSet<i64>,
        out: &mut Vec<CredRow>,
    ) {
        if depth >= MAX_DEPTH {
            return;
        }
        if !self.folder_has_match(folder, q, matching_cred_ids, 0) {
            return;
        }
        out.push(CredRow {
            id: folder.id.get() as i32,
            label: SharedString::from(folder.name.as_str()),
            kind: SharedString::from(""),
            username: SharedString::from(""),
            is_folder: true,
            expanded: true,
            selected: false,
            depth: depth as i32,
        });
        let mut sub_folders: Vec<&CredentialFolder> = self
            .folders
            .iter()
            .filter(|f| f.parent_id == Some(folder.id))
            .collect();
        sub_folders.sort_by_key(|f| (f.sort, f.id.get()));
        for sf in sub_folders {
            self.push_folder_filtered(sf, depth + 1, q, matching_cred_ids, out);
        }
        let mut folder_creds: Vec<&Credential> = self
            .credentials
            .iter()
            .filter(|c| c.folder_id == Some(folder.id) && matching_cred_ids.contains(&c.id.get()))
            .collect();
        folder_creds.sort_by_key(|c| c.id.get());
        for cred in folder_creds {
            out.push(self.make_cred_row(cred, depth + 1));
        }
    }

    pub fn folders(&self) -> &[CredentialFolder] {
        &self.folders
    }

    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    /// Resolve the effective credential id for a connection:
    ///   1. `conn_cred_id` if set, else
    ///   2. the nearest ancestor group's `default_credential`, else
    ///   3. None.
    ///
    /// Returns `(effective_id, inherited)` where `inherited` is true when the
    /// credential comes from a group default rather than the connection itself.
    pub fn resolve_effective(
        conn_cred_id: Option<CredentialId>,
        conn_group_id: Option<cm_core::GroupId>,
        groups: &[cm_core::Group],
    ) -> (Option<CredentialId>, bool) {
        if let Some(id) = conn_cred_id {
            return (Some(id), false);
        }
        // Walk the ancestor chain.
        let max_depth = groups.len().max(1);
        let mut current_gid = conn_group_id;
        for _ in 0..max_depth {
            let Some(gid) = current_gid else { break };
            let Some(group) = groups.iter().find(|g| g.id == gid) else {
                break;
            };
            if let Some(cred) = group.default_credential {
                return (Some(cred), true);
            }
            current_gid = group.parent_id;
        }
        (None, false)
    }

    /// Display name for a credential id (or "<deleted>" / "").
    pub fn cred_display_name(cred_id: Option<CredentialId>, credentials: &[Credential]) -> String {
        match cred_id {
            None => String::new(),
            Some(id) => credentials
                .iter()
                .find(|c| c.id == id)
                .map(|c| c.name.as_str())
                .unwrap_or("<deleted>")
                .to_owned(),
        }
    }

    /// Build the flat folder name list for the credential editor's folder picker.
    /// Index 0 = "Root (no folder)"; subsequent entries are folder names.
    pub fn build_folder_name_list(folders: &[CredentialFolder]) -> Vec<SharedString> {
        let mut out = vec![SharedString::from("Root (no folder)")];
        let mut sorted: Vec<&CredentialFolder> = folders.iter().collect();
        sorted.sort_by_key(|f| (f.sort, f.id.get()));
        for f in sorted {
            out.push(SharedString::from(f.name.as_str()));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::{Credential, CredentialFolder, CredentialFolderId, CredentialId, CredentialKind};

    fn folder(id: i64, parent: Option<i64>, name: &str) -> CredentialFolder {
        CredentialFolder {
            id: CredentialFolderId::new(id),
            parent_id: parent.map(CredentialFolderId::new),
            name: name.to_owned(),
            sort: 0,
        }
    }

    fn cred(id: i64, folder_id: Option<i64>, name: &str, kind: CredentialKind) -> Credential {
        Credential {
            id: CredentialId::new(id),
            name: name.to_owned(),
            kind,
            folder_id: folder_id.map(CredentialFolderId::new),
            username: Some("user".to_owned()),
        }
    }

    #[test]
    fn flat_empty_panel() {
        let panel = KeysPanel::new(vec![], vec![]);
        assert!(panel.flat().is_empty());
    }

    #[test]
    fn flat_folder_with_credentials_expanded() {
        let folders = vec![folder(1, None, "Work")];
        let creds = vec![
            cred(10, Some(1), "ops-pass", CredentialKind::Password),
            cred(11, Some(1), "deploy-key", CredentialKind::SshKey),
        ];
        let panel = KeysPanel::new(folders, creds);
        let flat = panel.flat();
        assert_eq!(flat.len(), 3);
        assert!(flat[0].is_folder);
        assert_eq!(flat[0].label.as_str(), "Work");
        assert!(!flat[1].is_folder);
        assert!(!flat[2].is_folder);
    }

    #[test]
    fn flat_subfolder_depth() {
        let folders = vec![folder(1, None, "Root"), folder(2, Some(1), "Sub")];
        let creds = vec![
            cred(10, Some(1), "root-cred", CredentialKind::Password),
            cred(20, Some(2), "sub-cred", CredentialKind::SshKey),
        ];
        let mut panel = KeysPanel::new(folders, creds);
        panel.expanded.insert(2);
        let flat = panel.flat();
        assert_eq!(flat.len(), 4);
        assert_eq!(flat[0].depth, 0); // Root folder
        assert_eq!(flat[1].depth, 1); // Sub folder
        assert_eq!(flat[2].depth, 2); // sub-cred
        assert_eq!(flat[3].depth, 1); // root-cred
    }

    #[test]
    fn toggle_folder_hides_children() {
        let folders = vec![folder(1, None, "Work")];
        let creds = vec![cred(10, Some(1), "pass", CredentialKind::Password)];
        let mut panel = KeysPanel::new(folders, creds);
        assert_eq!(panel.flat().len(), 2);
        panel.toggle_expand(1);
        assert_eq!(panel.flat().len(), 1);
        panel.toggle_expand(1);
        assert_eq!(panel.flat().len(), 2);
    }

    #[test]
    fn cred_kind_strings() {
        let creds = vec![
            cred(1, None, "a", CredentialKind::Password),
            cred(2, None, "b", CredentialKind::SshKey),
            cred(3, None, "c", CredentialKind::SshKeyWithPassphrase),
        ];
        let panel = KeysPanel::new(vec![], creds);
        let flat = panel.flat();
        assert_eq!(flat[0].kind.as_str(), "Password");
        assert_eq!(flat[1].kind.as_str(), "SSH Key");
        assert_eq!(flat[2].kind.as_str(), "SSH Key+PP");
    }

    #[test]
    fn effective_cred_direct() {
        // Direct: connection has its own credential, not inherited.
        let (id, inherited) = KeysPanel::resolve_effective(Some(CredentialId::new(5)), None, &[]);
        assert_eq!(id, Some(CredentialId::new(5)));
        assert!(!inherited);
    }

    #[test]
    fn effective_cred_inherited_from_group() {
        use cm_core::{Group, GroupId};
        let group = Group {
            id: GroupId::new(1),
            parent_id: None,
            name: "Lab".to_owned(),
            sort: 0,
            default_credential: Some(CredentialId::new(99)),
        };
        let (id, inherited) = KeysPanel::resolve_effective(None, Some(GroupId::new(1)), &[group]);
        assert_eq!(id, Some(CredentialId::new(99)));
        assert!(inherited, "should be inherited from group");
    }

    #[test]
    fn effective_cred_none() {
        let (id, inherited) = KeysPanel::resolve_effective(None, None, &[]);
        assert_eq!(id, None);
        assert!(!inherited);
    }

    #[test]
    fn effective_cred_display_deleted() {
        let name = KeysPanel::cred_display_name(Some(CredentialId::new(999)), &[]);
        assert_eq!(name, "<deleted>");
    }

    #[test]
    fn effective_cred_display_found() {
        let creds = vec![cred(5, None, "my-key", CredentialKind::SshKey)];
        let name = KeysPanel::cred_display_name(Some(CredentialId::new(5)), &creds);
        assert_eq!(name, "my-key");
    }

    #[test]
    fn folder_name_list_includes_sentinel() {
        let folders = vec![folder(1, None, "Work"), folder(2, None, "Personal")];
        let list = KeysPanel::build_folder_name_list(&folders);
        assert_eq!(list[0].as_str(), "Root (no folder)");
        assert!(list.len() >= 3);
    }

    #[test]
    fn inheritance_display_from_grandparent() {
        use cm_core::{Group, GroupId};
        // Connection in child group; grandparent group has default credential.
        let parent = Group {
            id: GroupId::new(1),
            parent_id: None,
            name: "Root".to_owned(),
            sort: 0,
            default_credential: Some(CredentialId::new(42)),
        };
        let child = Group {
            id: GroupId::new(2),
            parent_id: Some(GroupId::new(1)),
            name: "Child".to_owned(),
            sort: 0,
            default_credential: None,
        };
        let (id, inherited) =
            KeysPanel::resolve_effective(None, Some(GroupId::new(2)), &[parent, child]);
        assert_eq!(id, Some(CredentialId::new(42)));
        assert!(inherited);
    }
}
