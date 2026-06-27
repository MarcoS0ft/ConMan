//! Public-surface tests for the `cm-core` domain model and ports.
//!
//! These run as an external crate, so they exercise only the public API and, in
//! particular, prove that `ConnectionRepository` is object-safe.

use std::sync::Mutex;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionRepository, ConnectionSettings,
    CredentialPurpose, CredentialRef, DomainError, Group, GroupId, LocalSettings, RdpSettings,
    RepositoryError, Secret, SshAuthMethod, SshSettings,
};

fn rdp_settings() -> ConnectionSettings {
    ConnectionSettings::Rdp(RdpSettings {
        host: "host.example".to_string(),
        port: RdpSettings::DEFAULT_PORT,
        domain: Some("CORP".to_string()),
        username: Some("alice".to_string()),
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

    let key_ref = CredentialRef::new(ConnectionId::new(5), CredentialPurpose::SshKey);
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

#[test]
fn credential_ref_format_is_pinned() {
    let cref = CredentialRef::new(ConnectionId::new(12), CredentialPurpose::Password);
    assert_eq!(cref.service(), "conman");
    assert_eq!(cref.service(), CredentialRef::SERVICE);
    assert_eq!(cref.account(), "12:password");

    assert_eq!(CredentialPurpose::SshKey.as_str(), "ssh-key");
    assert_eq!(CredentialPurpose::SshPassphrase.as_str(), "ssh-passphrase");

    // Round-trip.
    let json = serde_json::to_string(&cref).unwrap();
    assert_eq!(serde_json::from_str::<CredentialRef>(&json).unwrap(), cref);
}

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
        "credential_ref": null,
        "sort": 0,
        "created_at": 0,
        "updated_at": 0
    }"#;
    let conn: Connection = serde_json::from_str(json).unwrap();
    assert!(conn.validate().is_err());
}

#[test]
fn connection_round_trips_through_json() {
    let original = Connection::new(
        ConnectionId::new(99),
        Some(GroupId::new(4)),
        "prod-jump".to_string(),
        ConnectionKind::Ssh,
        ssh_settings(SshAuthMethod::PublicKey {
            key_ref: CredentialRef::new(ConnectionId::new(99), CredentialPurpose::SshKey),
        }),
        Some(CredentialRef::new(
            ConnectionId::new(99),
            CredentialPurpose::SshPassphrase,
        )),
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
    let group = Group {
        id: GroupId::new(1),
        parent_id: None,
        name: "root".to_string(),
        sort: 0,
    };
    let json = serde_json::to_string(&group).unwrap();
    assert_eq!(serde_json::from_str::<Group>(&json).unwrap(), group);
}

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
    fn list_groups(&self) -> Result<Vec<Group>, RepositoryError> {
        Ok(self.groups.lock().unwrap().clone())
    }

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

    fn delete_group(&self, id: GroupId) -> Result<(), RepositoryError> {
        self.groups.lock().unwrap().retain(|g| g.id != id);
        Ok(())
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
