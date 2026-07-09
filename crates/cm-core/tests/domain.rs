//! Public-surface tests for the `cm-core` domain model and ports.
//!
//! These run as an external crate, so they exercise only the public API and, in
//! particular, prove that `ConnectionRepository` is object-safe.

use std::sync::Mutex;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionRepository, ConnectionSettings, Credential,
    CredentialFolder, CredentialFolderId, CredentialId, CredentialKind, CredentialPurpose,
    CredentialRef, CredentialSource, DomainError, Group, GroupId, LocalSettings, RdpSettings,
    RepositoryError, Secret, SshAuthMethod, SshSettings, resolve_effective_credential,
};

fn rdp_settings() -> ConnectionSettings {
    ConnectionSettings::Rdp(RdpSettings {
        host: "host.example".to_string(),
        port: RdpSettings::DEFAULT_PORT,
        domain: Some("CORP".to_string()),
        username: Some("alice".to_string()),
        ..RdpSettings::default()
    })
}

fn ssh_settings(auth: SshAuthMethod) -> ConnectionSettings {
    ConnectionSettings::Ssh(SshSettings {
        host: "ssh.example".to_string(),
        port: SshSettings::DEFAULT_PORT,
        username: "bob".to_string(),
        auth_method: auth,
    })
}

fn make_group(id: i64, parent_id: Option<i64>, default_credential: Option<i64>) -> Group {
    Group {
        id: GroupId::new(id),
        parent_id: parent_id.map(GroupId::new),
        name: format!("group-{id}"),
        sort: 0,
        default_credential: default_credential.map(CredentialId::new),
    }
}

fn make_connection(group_id: Option<i64>, credential: Option<i64>) -> Connection {
    Connection::new(
        ConnectionId::UNSAVED,
        group_id.map(GroupId::new),
        "test-conn".to_string(),
        ConnectionKind::LocalTerminal,
        ConnectionSettings::Local(LocalSettings::default()),
        credential.map(|id| CredentialSource::Object(CredentialId::new(id))),
        0,
        0,
        0,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// ID newtype behaviour
// ---------------------------------------------------------------------------

#[test]
fn id_newtype_behavior() {
    assert_eq!(ConnectionId::UNSAVED.get(), 0);
    assert!(ConnectionId::UNSAVED.is_unsaved());
    assert!(!ConnectionId::new(7).is_unsaved());
    assert_eq!(ConnectionId::new(7).get(), 7);

    assert_eq!(GroupId::UNSAVED.get(), 0);
    assert!(GroupId::UNSAVED.is_unsaved());
    assert!(!GroupId::new(3).is_unsaved());

    // `#[serde(transparent)]` — serializes as the bare integer.
    assert_eq!(serde_json::to_string(&ConnectionId::new(42)).unwrap(), "42");
    assert_eq!(
        serde_json::from_str::<ConnectionId>("42").unwrap(),
        ConnectionId::new(42)
    );
}

#[test]
fn credential_id_newtype_behavior() {
    assert_eq!(CredentialId::UNSAVED.get(), 0);
    assert!(CredentialId::UNSAVED.is_unsaved());
    assert!(!CredentialId::new(1).is_unsaved());
    assert_eq!(CredentialId::new(99).get(), 99);

    // Transparent serde.
    assert_eq!(serde_json::to_string(&CredentialId::new(7)).unwrap(), "7");
    assert_eq!(
        serde_json::from_str::<CredentialId>("7").unwrap(),
        CredentialId::new(7)
    );
}

#[test]
fn credential_folder_id_newtype_behavior() {
    assert_eq!(CredentialFolderId::UNSAVED.get(), 0);
    assert!(CredentialFolderId::UNSAVED.is_unsaved());
    assert!(!CredentialFolderId::new(2).is_unsaved());
    assert_eq!(CredentialFolderId::new(42).get(), 42);

    assert_eq!(
        serde_json::to_string(&CredentialFolderId::new(5)).unwrap(),
        "5"
    );
    assert_eq!(
        serde_json::from_str::<CredentialFolderId>("5").unwrap(),
        CredentialFolderId::new(5)
    );
}

// ---------------------------------------------------------------------------
// CredentialKind serde tags (pinned)
// ---------------------------------------------------------------------------

#[test]
fn credential_kind_tag_strings_are_pinned() {
    assert_eq!(
        serde_json::to_string(&CredentialKind::Password).unwrap(),
        "\"password\""
    );
    assert_eq!(
        serde_json::to_string(&CredentialKind::SshKey).unwrap(),
        "\"ssh-key\""
    );
    assert_eq!(
        serde_json::to_string(&CredentialKind::SshKeyWithPassphrase).unwrap(),
        "\"ssh-key-with-passphrase\""
    );

    assert_eq!(
        serde_json::from_str::<CredentialKind>("\"password\"").unwrap(),
        CredentialKind::Password
    );
    assert_eq!(
        serde_json::from_str::<CredentialKind>("\"ssh-key\"").unwrap(),
        CredentialKind::SshKey
    );
    assert_eq!(
        serde_json::from_str::<CredentialKind>("\"ssh-key-with-passphrase\"").unwrap(),
        CredentialKind::SshKeyWithPassphrase
    );
}

// ---------------------------------------------------------------------------
// Credential and CredentialFolder round-trips
// ---------------------------------------------------------------------------

#[test]
fn credential_round_trips_through_json() {
    let cred = Credential {
        id: CredentialId::new(3),
        name: "prod-server-key".to_string(),
        kind: CredentialKind::SshKeyWithPassphrase,
        folder_id: Some(CredentialFolderId::new(1)),
        username: Some("deploy".to_string()),
    };
    let json = serde_json::to_string(&cred).unwrap();
    assert_eq!(serde_json::from_str::<Credential>(&json).unwrap(), cred);

    // No folder, no username.
    let cred2 = Credential {
        id: CredentialId::new(7),
        name: "vpn-pass".to_string(),
        kind: CredentialKind::Password,
        folder_id: None,
        username: None,
    };
    let json2 = serde_json::to_string(&cred2).unwrap();
    assert_eq!(serde_json::from_str::<Credential>(&json2).unwrap(), cred2);
}

#[test]
fn credential_folder_round_trips_through_json() {
    let folder = CredentialFolder {
        id: CredentialFolderId::new(2),
        parent_id: Some(CredentialFolderId::new(1)),
        name: "Work".to_string(),
        sort: 10,
    };
    let json = serde_json::to_string(&folder).unwrap();
    assert_eq!(
        serde_json::from_str::<CredentialFolder>(&json).unwrap(),
        folder
    );

    // Root-level folder.
    let root = CredentialFolder {
        id: CredentialFolderId::new(1),
        parent_id: None,
        name: "Root".to_string(),
        sort: 0,
    };
    let json = serde_json::to_string(&root).unwrap();
    assert_eq!(
        serde_json::from_str::<CredentialFolder>(&json).unwrap(),
        root
    );
}

// ---------------------------------------------------------------------------
// CredentialPurpose / CredentialRef (re-keyed)
// ---------------------------------------------------------------------------

#[test]
fn credential_ref_format_is_pinned() {
    // Account format is now "cred:<credential-id>:<purpose>".
    let cref = CredentialRef::new(CredentialId::new(12), CredentialPurpose::Password);
    assert_eq!(cref.service(), "conman");
    assert_eq!(cref.service(), CredentialRef::SERVICE);
    assert_eq!(cref.account(), "cred:12:password");

    assert_eq!(CredentialPurpose::SshKey.as_str(), "ssh-key");
    assert_eq!(CredentialPurpose::SshPassphrase.as_str(), "ssh-passphrase");

    // All purposes produce the correct prefix.
    let ssh_key = CredentialRef::new(CredentialId::new(5), CredentialPurpose::SshKey);
    assert_eq!(ssh_key.account(), "cred:5:ssh-key");

    let passphrase = CredentialRef::new(CredentialId::new(5), CredentialPurpose::SshPassphrase);
    assert_eq!(passphrase.account(), "cred:5:ssh-passphrase");

    // Round-trip.
    let json = serde_json::to_string(&cref).unwrap();
    assert_eq!(serde_json::from_str::<CredentialRef>(&json).unwrap(), cref);
}

#[test]
fn credential_ref_for_connection_format_and_purpose_str() {
    // P9.6-A: connection-scoped refs use "conn:" not "cred:", so they never
    // collide with an object credential's keychain slot.
    let inline = CredentialRef::for_connection(ConnectionId::new(7), CredentialPurpose::Password);
    assert_eq!(inline.service(), "conman");
    assert_eq!(inline.account(), "conn:7:password");

    // purpose_str() is the one piece of a CredentialRef that's safe to log
    // (P9.8 H2-H6) — never the full account(), which encodes id material.
    assert_eq!(inline.purpose_str(), Some("password"));
    let object = CredentialRef::new(CredentialId::new(9), CredentialPurpose::SshPassphrase);
    assert_eq!(object.purpose_str(), Some("ssh-passphrase"));
}

// ---------------------------------------------------------------------------
// ConnectionKind / SshAuthMethod
// ---------------------------------------------------------------------------

#[test]
fn connection_kind_tag_strings_are_pinned() {
    assert_eq!(
        serde_json::to_string(&ConnectionKind::Rdp).unwrap(),
        "\"rdp\""
    );
    assert_eq!(
        serde_json::to_string(&ConnectionKind::Ssh).unwrap(),
        "\"ssh\""
    );
    assert_eq!(
        serde_json::to_string(&ConnectionKind::LocalTerminal).unwrap(),
        "\"local\""
    );

    assert_eq!(
        serde_json::from_str::<ConnectionKind>("\"local\"").unwrap(),
        ConnectionKind::LocalTerminal
    );
}

#[test]
fn ssh_auth_method_tag_strings_are_pinned() {
    let password = serde_json::to_value(SshAuthMethod::Password).unwrap();
    assert_eq!(password["method"], "password");

    let agent = serde_json::to_value(SshAuthMethod::Agent).unwrap();
    assert_eq!(agent["method"], "agent");

    // CredentialRef now keyed by CredentialId.
    let key_ref = CredentialRef::new(CredentialId::new(5), CredentialPurpose::SshKey);
    let public_key = serde_json::to_value(SshAuthMethod::PublicKey {
        key_ref: key_ref.clone(),
    })
    .unwrap();
    assert_eq!(public_key["method"], "public_key");

    // Round-trips back to the same value.
    let restored: SshAuthMethod = serde_json::from_value(public_key).unwrap();
    assert_eq!(restored, SshAuthMethod::PublicKey { key_ref });
}

#[test]
fn connection_settings_external_tags_are_pinned() {
    let rdp = serde_json::to_value(rdp_settings()).unwrap();
    assert!(rdp.get("rdp").is_some());

    let local = serde_json::to_value(ConnectionSettings::Local(LocalSettings::default())).unwrap();
    assert!(local.get("local").is_some());

    let ssh = serde_json::to_value(ssh_settings(SshAuthMethod::Agent)).unwrap();
    assert!(ssh.get("ssh").is_some());
}

// ---------------------------------------------------------------------------
// Connection validation and round-trips
// ---------------------------------------------------------------------------

#[test]
fn connection_rejects_kind_settings_mismatch() {
    // ssh kind with rdp settings must be rejected.
    let err = Connection::new(
        ConnectionId::UNSAVED,
        None,
        "mismatch".to_string(),
        ConnectionKind::Ssh,
        rdp_settings(),
        None,
        0,
        0,
        0,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DomainError::SettingsKindMismatch {
            expected: ConnectionKind::Ssh,
            found: ConnectionKind::Rdp,
        }
    ));

    // Matching kind/settings is accepted.
    let ok = Connection::new(
        ConnectionId::UNSAVED,
        None,
        "good".to_string(),
        ConnectionKind::Rdp,
        rdp_settings(),
        None,
        0,
        0,
        0,
    );
    assert!(ok.is_ok());
}

#[test]
fn validate_catches_tampered_deserialized_connection() {
    // Simulate untrusted input: kind says ssh, settings say local.
    let json = r#"{
        "id": 0,
        "group_id": null,
        "name": "tampered",
        "kind": "ssh",
        "settings": { "local": { "program": null, "args": [], "working_dir": null, "env": [] } },
        "credential": null,
        "sort": 0,
        "created_at": 0,
        "updated_at": 0
    }"#;
    let conn: Connection = serde_json::from_str(json).unwrap();
    assert!(conn.validate().is_err());
}

#[test]
fn connection_round_trips_through_json() {
    // Connection with an explicit credential id and SSH PublicKey method.
    let original = Connection::new(
        ConnectionId::new(99),
        Some(GroupId::new(4)),
        "prod-jump".to_string(),
        ConnectionKind::Ssh,
        ssh_settings(SshAuthMethod::PublicKey {
            key_ref: CredentialRef::new(CredentialId::new(5), CredentialPurpose::SshKey),
        }),
        Some(CredentialSource::Object(CredentialId::new(5))),
        2,
        1_700_000_000,
        1_700_000_001,
    )
    .unwrap();

    let json = serde_json::to_string(&original).unwrap();
    let restored: Connection = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, original);
    assert!(restored.validate().is_ok());
}

#[test]
fn group_round_trips_through_json() {
    // Group with a default credential.
    let group = Group {
        id: GroupId::new(1),
        parent_id: None,
        name: "root".to_string(),
        sort: 0,
        default_credential: Some(CredentialId::new(3)),
    };
    let json = serde_json::to_string(&group).unwrap();
    assert_eq!(serde_json::from_str::<Group>(&json).unwrap(), group);

    // Group with no default credential.
    let group_no_cred = Group {
        id: GroupId::new(2),
        parent_id: Some(GroupId::new(1)),
        name: "sub".to_string(),
        sort: 1,
        default_credential: None,
    };
    let json2 = serde_json::to_string(&group_no_cred).unwrap();
    assert_eq!(
        serde_json::from_str::<Group>(&json2).unwrap(),
        group_no_cred
    );
}

// ---------------------------------------------------------------------------
// resolve_effective_credential
// ---------------------------------------------------------------------------

#[test]
fn resolve_uses_connection_credential_when_set() {
    let groups = [make_group(1, None, Some(10))];
    let conn = make_connection(Some(1), Some(42));
    // Connection has explicit credential — ignore group default.
    assert_eq!(
        resolve_effective_credential(&conn, &groups),
        Some(CredentialId::new(42))
    );
}

#[test]
fn resolve_inherits_from_direct_group() {
    let groups = [make_group(1, None, Some(10))];
    let conn = make_connection(Some(1), None);
    assert_eq!(
        resolve_effective_credential(&conn, &groups),
        Some(CredentialId::new(10))
    );
}

#[test]
fn resolve_inherits_from_ancestor_group() {
    // grandparent(id=1, cred=7) <- parent(id=2, cred=None) <- conn(group=2)
    let groups = [make_group(1, None, Some(7)), make_group(2, Some(1), None)];
    let conn = make_connection(Some(2), None);
    assert_eq!(
        resolve_effective_credential(&conn, &groups),
        Some(CredentialId::new(7))
    );
}

#[test]
fn resolve_connection_credential_overrides_ancestor() {
    // grandparent(id=1, cred=7) <- parent(id=2, cred=10) <- conn(group=2, cred=99)
    let groups = [
        make_group(1, None, Some(7)),
        make_group(2, Some(1), Some(10)),
    ];
    let conn = make_connection(Some(2), Some(99));
    assert_eq!(
        resolve_effective_credential(&conn, &groups),
        Some(CredentialId::new(99))
    );
}

#[test]
fn resolve_nearest_ancestor_wins() {
    // grandparent(id=1, cred=7) <- parent(id=2, cred=10) <- conn(group=2)
    // Parent is nearer than grandparent: cred 10 should win.
    let groups = [
        make_group(1, None, Some(7)),
        make_group(2, Some(1), Some(10)),
    ];
    let conn = make_connection(Some(2), None);
    assert_eq!(
        resolve_effective_credential(&conn, &groups),
        Some(CredentialId::new(10))
    );
}

#[test]
fn resolve_returns_none_when_no_credential_anywhere() {
    let groups = [make_group(1, None, None), make_group(2, Some(1), None)];
    let conn = make_connection(Some(2), None);
    assert_eq!(resolve_effective_credential(&conn, &groups), None);
}

#[test]
fn resolve_returns_none_for_root_connection_with_no_credential() {
    // Connection at root level (no group) with no credential.
    let conn = make_connection(None, None);
    assert_eq!(resolve_effective_credential(&conn, &[]), None);
}

#[test]
fn resolve_is_cycle_safe() {
    // Fabricate a cycle: group 1 parent → 2, group 2 parent → 1.
    // Neither has a default_credential. The bounded walk must terminate.
    let groups = [make_group(1, Some(2), None), make_group(2, Some(1), None)];
    let conn = make_connection(Some(1), None);
    // Should return None (not hang) even though the parent chain is cyclic.
    assert_eq!(resolve_effective_credential(&conn, &groups), None);
}

// ---------------------------------------------------------------------------
// Secret hygiene
// ---------------------------------------------------------------------------

#[test]
fn secret_redacts_and_does_not_leak() {
    let secret = Secret::from_string("hunter2".to_string());

    assert_eq!(secret.expose(), b"hunter2");

    let debug = format!("{secret:?}");
    let display = format!("{secret}");
    assert!(!debug.contains("hunter2"));
    assert!(!display.contains("hunter2"));
    assert!(debug.contains("redacted"));
    assert!(display.contains("redacted"));

    // Byte constructor preserves arbitrary (non-utf8) content.
    let raw = Secret::new(vec![0u8, 159, 146, 150]);
    assert_eq!(raw.expose(), &[0u8, 159, 146, 150]);
    assert!(!format!("{raw:?}").contains("159"));
}

// ---------------------------------------------------------------------------
// ConnectionRepository object-safety and ergonomics
// ---------------------------------------------------------------------------

/// Test-only in-memory fake proving `ConnectionRepository` is object-safe and
/// ergonomic. Not a deliverable adapter.
#[derive(Debug, Default)]
struct InMemoryRepo {
    groups: Mutex<Vec<Group>>,
    connections: Mutex<Vec<Connection>>,
    next_group_id: Mutex<i64>,
    next_conn_id: Mutex<i64>,
}

impl ConnectionRepository for InMemoryRepo {
    // --- Connections ---

    fn list_connections(&self) -> Result<Vec<Connection>, RepositoryError> {
        Ok(self.connections.lock().unwrap().clone())
    }

    fn get_connection(&self, id: ConnectionId) -> Result<Option<Connection>, RepositoryError> {
        Ok(self
            .connections
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.id == id)
            .cloned())
    }

    fn upsert_connection(&self, conn: &Connection) -> Result<ConnectionId, RepositoryError> {
        let mut conns = self.connections.lock().unwrap();
        if conn.id.is_unsaved() {
            let mut next = self.next_conn_id.lock().unwrap();
            *next += 1;
            let id = ConnectionId::new(*next);
            let mut stored = conn.clone();
            stored.id = id;
            conns.push(stored);
            Ok(id)
        } else if let Some(slot) = conns.iter_mut().find(|c| c.id == conn.id) {
            *slot = conn.clone();
            Ok(conn.id)
        } else {
            Err(RepositoryError::NotFound)
        }
    }

    fn delete_connection(&self, id: ConnectionId) -> Result<(), RepositoryError> {
        self.connections.lock().unwrap().retain(|c| c.id != id);
        Ok(())
    }

    fn move_connection(
        &self,
        id: ConnectionId,
        new_group: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError> {
        let mut conns = self.connections.lock().unwrap();
        let slot = conns
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(RepositoryError::NotFound)?;
        slot.group_id = new_group;
        slot.sort = new_sort;
        Ok(())
    }

    // --- Groups ---

    fn list_groups(&self) -> Result<Vec<Group>, RepositoryError> {
        Ok(self.groups.lock().unwrap().clone())
    }

    fn get_group(&self, id: GroupId) -> Result<Option<Group>, RepositoryError> {
        Ok(self
            .groups
            .lock()
            .unwrap()
            .iter()
            .find(|g| g.id == id)
            .cloned())
    }

    fn upsert_group(&self, group: &Group) -> Result<GroupId, RepositoryError> {
        let mut groups = self.groups.lock().unwrap();
        if group.id.is_unsaved() {
            let mut next = self.next_group_id.lock().unwrap();
            *next += 1;
            let id = GroupId::new(*next);
            let mut stored = group.clone();
            stored.id = id;
            groups.push(stored);
            Ok(id)
        } else if let Some(slot) = groups.iter_mut().find(|g| g.id == group.id) {
            *slot = group.clone();
            Ok(group.id)
        } else {
            Err(RepositoryError::NotFound)
        }
    }

    fn delete_group(&self, id: GroupId) -> Result<(), RepositoryError> {
        self.groups.lock().unwrap().retain(|g| g.id != id);
        Ok(())
    }

    fn move_group(
        &self,
        id: GroupId,
        new_parent: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError> {
        let mut groups = self.groups.lock().unwrap();
        let slot = groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(RepositoryError::NotFound)?;
        slot.parent_id = new_parent;
        slot.sort = new_sort;
        Ok(())
    }

    // --- Credentials (stubs — this fake does not store credentials) ---

    fn list_credentials(&self) -> Result<Vec<Credential>, RepositoryError> {
        Ok(Vec::new())
    }

    fn get_credential(&self, _id: CredentialId) -> Result<Option<Credential>, RepositoryError> {
        Ok(None)
    }

    fn upsert_credential(&self, _cred: &Credential) -> Result<CredentialId, RepositoryError> {
        Err(RepositoryError::Backend(
            "not implemented in InMemoryRepo".into(),
        ))
    }

    fn delete_credential(&self, _id: CredentialId) -> Result<(), RepositoryError> {
        Ok(())
    }

    // --- Credential folders (stubs) ---

    fn list_credential_folders(&self) -> Result<Vec<CredentialFolder>, RepositoryError> {
        Ok(Vec::new())
    }

    fn get_credential_folder(
        &self,
        _id: CredentialFolderId,
    ) -> Result<Option<CredentialFolder>, RepositoryError> {
        Ok(None)
    }

    fn upsert_credential_folder(
        &self,
        _folder: &CredentialFolder,
    ) -> Result<CredentialFolderId, RepositoryError> {
        Err(RepositoryError::Backend(
            "not implemented in InMemoryRepo".into(),
        ))
    }

    fn delete_credential_folder(&self, _id: CredentialFolderId) -> Result<(), RepositoryError> {
        Ok(())
    }

    fn move_credential_folder(
        &self,
        _id: CredentialFolderId,
        _new_parent: Option<CredentialFolderId>,
        _new_sort: i64,
    ) -> Result<(), RepositoryError> {
        Err(RepositoryError::NotFound)
    }

    // --- Inheritance resolution (stub) ---

    fn resolve_effective_credential(
        &self,
        _conn_id: ConnectionId,
    ) -> Result<Option<CredentialId>, RepositoryError> {
        Ok(None)
    }

    // --- Settings (stubs) ---

    fn get_setting(&self, _key: &str) -> Result<Option<String>, RepositoryError> {
        Ok(None)
    }

    fn set_setting(&self, _key: &str, _value: &str) -> Result<(), RepositoryError> {
        Err(RepositoryError::Backend(
            "not implemented in InMemoryRepo".into(),
        ))
    }

    fn list_settings(&self) -> Result<Vec<(String, String)>, RepositoryError> {
        Ok(Vec::new())
    }

    // --- Recents (stub) ---

    fn record_recent(&self, _id: ConnectionId, _opened_at: i64) -> Result<(), RepositoryError> {
        Ok(())
    }

    fn list_recents(&self, _limit: usize) -> Result<Vec<(ConnectionId, i64)>, RepositoryError> {
        Ok(Vec::new())
    }
}

#[test]
fn repository_is_object_safe_and_ergonomic() {
    let repo: Box<dyn ConnectionRepository> = Box::new(InMemoryRepo::default());

    let gid = repo
        .upsert_group(&Group {
            id: GroupId::UNSAVED,
            parent_id: None,
            name: "servers".to_string(),
            sort: 0,
            default_credential: None,
        })
        .unwrap();
    assert_eq!(gid, GroupId::new(1));

    let conn = Connection::new(
        ConnectionId::UNSAVED,
        Some(gid),
        "box".to_string(),
        ConnectionKind::LocalTerminal,
        ConnectionSettings::Local(LocalSettings::default()),
        None,
        0,
        0,
        0,
    )
    .unwrap();
    let cid = repo.upsert_connection(&conn).unwrap();
    assert_eq!(cid, ConnectionId::new(1));

    assert_eq!(repo.list_groups().unwrap().len(), 1);
    assert_eq!(repo.get_connection(cid).unwrap().unwrap().id, cid);

    repo.move_connection(cid, None, 5).unwrap();
    let moved = repo.get_connection(cid).unwrap().unwrap();
    assert_eq!(moved.group_id, None);
    assert_eq!(moved.sort, 5);

    assert!(matches!(
        repo.move_group(GroupId::new(999), None, 0),
        Err(RepositoryError::NotFound)
    ));

    repo.delete_connection(cid).unwrap();
    assert!(repo.get_connection(cid).unwrap().is_none());
}
