//! Integration tests for [`SqliteRepository`].
//!
//! Each test opens a fresh in-memory database so tests are independent.
//! Covers: CRUD, nested-tree create/move/delete, cycle rejection, credential
//! sharing, inheritance resolution through the repository, and ordering.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cm_core::{
    AppStateRepository, Connection, ConnectionId, ConnectionKind, ConnectionRepository,
    ConnectionSettings, Credential, CredentialError, CredentialFolder, CredentialFolderId,
    CredentialId, CredentialKind, CredentialPurpose, CredentialRef, CredentialSource,
    CredentialStore, Group, GroupId, LocalSettings, RdpSettings, RepositoryError, Secret,
    SshAuthMethod, SshSettings, TelnetSettings,
};
use cm_storage::SqliteRepository;

/// Minimal mock keychain (mirrors the pattern used by `tests/import_csv.rs`
/// etc.) for [`SqliteRepository::with_credential_store`]'s
/// delete-connection-cleanup test.
#[derive(Default)]
struct MockStore {
    data: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl CredentialStore for MockStore {
    fn store(&self, key: &CredentialRef, secret: &Secret) -> Result<(), CredentialError> {
        self.data.lock().expect("lock").insert(
            (key.service().to_string(), key.account().to_string()),
            secret.expose().to_vec(),
        );
        Ok(())
    }

    fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(key.service().to_string(), key.account().to_string()))
            .cloned()
            .map(Secret::new))
    }

    fn delete(&self, key: &CredentialRef) -> Result<(), CredentialError> {
        self.data
            .lock()
            .expect("lock")
            .remove(&(key.service().to_string(), key.account().to_string()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn repo() -> SqliteRepository {
    SqliteRepository::open_in_memory().expect("open in-memory DB")
}

fn mk_group(name: &str, parent: Option<GroupId>, default_cred: Option<CredentialId>) -> Group {
    Group {
        id: GroupId::UNSAVED,
        parent_id: parent,
        name: name.to_string(),
        sort: 0,
        default_credential: default_cred,
    }
}

fn mk_local_conn(name: &str, group_id: Option<GroupId>) -> Connection {
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_string(),
        ConnectionKind::LocalTerminal,
        ConnectionSettings::Local(LocalSettings::default()),
        None,
        0,
        0,
        0,
    )
    .unwrap()
}

fn mk_rdp_conn(name: &str, group_id: Option<GroupId>, cred: Option<CredentialId>) -> Connection {
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_string(),
        ConnectionKind::Rdp,
        ConnectionSettings::Rdp(RdpSettings {
            host: "10.0.0.1".to_string(),
            port: RdpSettings::DEFAULT_PORT,
            domain: None,
            username: Some("admin".to_string()),
            ..RdpSettings::default()
        }),
        cred.map(CredentialSource::Object),
        0,
        0,
        0,
    )
    .unwrap()
}

fn mk_ssh_conn(name: &str, group_id: Option<GroupId>, cred: Option<CredentialId>) -> Connection {
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_string(),
        ConnectionKind::Ssh,
        ConnectionSettings::Ssh(SshSettings {
            host: "ssh.example".to_string(),
            port: SshSettings::DEFAULT_PORT,
            username: "user".to_string(),
            auth_method: SshAuthMethod::Password,
        }),
        cred.map(CredentialSource::Object),
        0,
        0,
        0,
    )
    .unwrap()
}

fn mk_telnet_conn(name: &str, group_id: Option<GroupId>) -> Connection {
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_string(),
        ConnectionKind::Telnet,
        ConnectionSettings::Telnet(TelnetSettings {
            host: "console.example".to_string(),
            port: TelnetSettings::DEFAULT_PORT,
        }),
        Some(CredentialSource::Prompt),
        0,
        0,
        0,
    )
    .unwrap()
}

#[test]
fn telnet_connection_round_trips_with_prompt_and_extracted_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("telnet.sqlite");
    let id = {
        let db = SqliteRepository::open(&path).expect("open repository");
        db.upsert_connection(&mk_telnet_conn("legacy console", None))
            .expect("insert telnet connection")
    };

    let raw = rusqlite::Connection::open(&path).expect("open raw database");
    let (kind, host, port): (String, Option<String>, Option<i64>) = raw
        .query_row(
            "SELECT kind, host, port FROM connections WHERE id = ?1",
            [id.get()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("raw endpoint columns");
    assert_eq!(
        (kind.as_str(), host.as_deref(), port),
        ("telnet", Some("console.example"), Some(23))
    );
    drop(raw);

    let db = SqliteRepository::open(&path).expect("reopen repository");
    let got = db.get_connection(id).expect("read").expect("present");
    assert_eq!(got.kind, ConnectionKind::Telnet);
    assert_eq!(got.credential_source, Some(CredentialSource::Prompt));
    assert_eq!(
        got.settings,
        ConnectionSettings::Telnet(TelnetSettings {
            host: "console.example".to_string(),
            port: 23,
        })
    );
}

fn mk_cred(name: &str, folder: Option<CredentialFolderId>) -> Credential {
    Credential {
        id: CredentialId::UNSAVED,
        name: name.to_string(),
        kind: CredentialKind::Password,
        folder_id: folder,
        username: Some("user".to_string()),
    }
}

fn mk_folder(name: &str, parent: Option<CredentialFolderId>) -> CredentialFolder {
    CredentialFolder {
        id: CredentialFolderId::UNSAVED,
        parent_id: parent,
        name: name.to_string(),
        sort: 0,
    }
}

// ---------------------------------------------------------------------------
// Group CRUD
// ---------------------------------------------------------------------------

#[test]
fn group_insert_and_read() {
    let db = repo();
    let id = db
        .upsert_group(&mk_group("servers", None, None))
        .expect("insert");
    assert!(!id.get_id().is_unsaved());

    let groups = db.list_groups().expect("list");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "servers");
    assert_eq!(groups[0].id, id.get_id());

    let got = db.get_group(id.get_id()).expect("get").expect("some");
    assert_eq!(got.name, "servers");
    assert_eq!(got.parent_id, None);
}

#[test]
fn group_update() {
    let db = repo();
    let id = db
        .upsert_group(&mk_group("old", None, None))
        .expect("insert");
    let updated = Group {
        id: id.get_id(),
        parent_id: None,
        name: "new".to_string(),
        sort: 5,
        default_credential: None,
    };
    let id2 = db.upsert_group(&updated).expect("update");
    assert_eq!(id2, id.get_id());
    let got = db.get_group(id.get_id()).expect("get").expect("some");
    assert_eq!(got.name, "new");
    assert_eq!(got.sort, 5);
}

#[test]
fn group_delete_empty_ok() {
    let db = repo();
    let id = db
        .upsert_group(&mk_group("to-delete", None, None))
        .expect("insert");
    db.delete_group(id.get_id()).expect("delete empty group");
    assert!(db.get_group(id.get_id()).expect("get").is_none());
}

#[test]
fn group_delete_not_found() {
    let db = repo();
    assert!(matches!(
        db.delete_group(GroupId::new(999)),
        Err(RepositoryError::NotFound)
    ));
}

// ---------------------------------------------------------------------------
// Connection CRUD
// ---------------------------------------------------------------------------

#[test]
fn connection_insert_rdp_round_trip() {
    let db = repo();
    let gid = db.upsert_group(&mk_group("g", None, None)).expect("group");
    let conn = mk_rdp_conn("prod", Some(gid.get_id()), None);
    let cid = db.upsert_connection(&conn).expect("insert");

    let got = db.get_connection(cid.get_id()).expect("get").expect("some");
    assert_eq!(got.name, "prod");
    assert_eq!(got.kind, ConnectionKind::Rdp);
    assert_eq!(got.group_id, Some(gid.get_id()));
    if let ConnectionSettings::Rdp(rdp) = &got.settings {
        assert_eq!(rdp.host, "10.0.0.1");
        assert_eq!(rdp.port, 3389);
    } else {
        panic!("expected RDP settings");
    }
}

#[test]
fn connection_insert_ssh_round_trip() {
    let db = repo();
    let conn = mk_ssh_conn("jump", None, None);
    let cid = db.upsert_connection(&conn).expect("insert");
    let got = db.get_connection(cid.get_id()).expect("get").expect("some");
    assert_eq!(got.kind, ConnectionKind::Ssh);
    if let ConnectionSettings::Ssh(ssh) = &got.settings {
        assert_eq!(ssh.host, "ssh.example");
    } else {
        panic!("expected SSH settings");
    }
}

#[test]
fn connection_insert_local_round_trip() {
    let db = repo();
    let conn = mk_local_conn("term", None);
    let cid = db.upsert_connection(&conn).expect("insert");
    let got = db.get_connection(cid.get_id()).expect("get").expect("some");
    assert_eq!(got.kind, ConnectionKind::LocalTerminal);
}

#[test]
fn connection_update() {
    let db = repo();
    let cid = db
        .upsert_connection(&mk_local_conn("old", None))
        .expect("insert");
    let updated = Connection::new(
        cid.get_id(),
        None,
        "updated".to_string(),
        ConnectionKind::LocalTerminal,
        ConnectionSettings::Local(LocalSettings::default()),
        None,
        10,
        0,
        1,
    )
    .unwrap();
    db.upsert_connection(&updated).expect("update");
    let got = db.get_connection(cid.get_id()).expect("get").expect("some");
    assert_eq!(got.name, "updated");
    assert_eq!(got.sort, 10);
    assert_eq!(got.updated_at, 1);
}

#[test]
fn connection_delete() {
    let db = repo();
    let cid = db
        .upsert_connection(&mk_local_conn("tmp", None))
        .expect("insert");
    db.delete_connection(cid.get_id()).expect("delete");
    assert!(db.get_connection(cid.get_id()).expect("get").is_none());
}

/// `delete_connection` also deletes the connection-scoped
/// inline-secret keychain entry when a [`CredentialStore`] is attached via
/// [`SqliteRepository::with_credential_store`] — the DB's `ON DELETE SET
/// NULL` only clears the credential-**object** FK; an inline secret lives
/// entirely outside SQLite and would otherwise be orphaned.
#[test]
fn connection_delete_also_deletes_the_inline_secret_keychain_entry() {
    let store = Arc::new(MockStore::default());
    let db = SqliteRepository::open_in_memory()
        .expect("open in-memory DB")
        .with_credential_store(store.clone() as Arc<dyn CredentialStore>);

    let conn = Connection::new(
        ConnectionId::UNSAVED,
        None,
        "inline-conn".to_string(),
        ConnectionKind::Ssh,
        ConnectionSettings::Ssh(SshSettings {
            host: "ssh.example".to_string(),
            port: SshSettings::DEFAULT_PORT,
            username: "svc".to_string(),
            auth_method: SshAuthMethod::Password,
        }),
        Some(CredentialSource::Inline {
            username: "svc".to_string(),
            domain: None,
            has_secret: true,
        }),
        0,
        0,
        0,
    )
    .expect("build connection");
    let cid = db.upsert_connection(&conn).expect("insert");

    let key = CredentialRef::for_connection(cid, CredentialPurpose::Password);
    store
        .store(&key, &Secret::from_string("inline-secret".to_string()))
        .expect("seed keychain entry");
    assert!(
        store.get(&key).expect("get").is_some(),
        "keychain entry should exist before delete"
    );

    db.delete_connection(cid).expect("delete connection");

    assert!(
        store.get(&key).expect("get").is_none(),
        "delete_connection must also delete the inline-secret keychain entry"
    );
}

/// Without an attached store, `delete_connection` remains safe: no keychain
/// interaction is attempted, and deletion still succeeds.
#[test]
fn connection_delete_without_a_credential_store_still_succeeds() {
    let db = repo();
    let cid = db
        .upsert_connection(&mk_local_conn("no-store", None))
        .expect("insert");
    db.delete_connection(cid.get_id()).expect("delete");
    assert!(db.get_connection(cid.get_id()).expect("get").is_none());
}

#[test]
fn connection_delete_not_found() {
    let db = repo();
    assert!(matches!(
        db.delete_connection(ConnectionId::new(999)),
        Err(RepositoryError::NotFound)
    ));
}

#[test]
fn connection_move() {
    let db = repo();
    let g1 = db.upsert_group(&mk_group("g1", None, None)).expect("g1");
    let g2 = db.upsert_group(&mk_group("g2", None, None)).expect("g2");
    let cid = db
        .upsert_connection(&mk_local_conn("c", Some(g1.get_id())))
        .expect("insert");

    db.move_connection(cid.get_id(), Some(g2.get_id()), 5)
        .expect("move");
    let got = db.get_connection(cid.get_id()).expect("get").expect("some");
    assert_eq!(got.group_id, Some(g2.get_id()));
    assert_eq!(got.sort, 5);
}

// ---------------------------------------------------------------------------
// Nested group tree
// ---------------------------------------------------------------------------

#[test]
fn nested_groups_create_and_list() {
    let db = repo();
    // root → servers → production
    let root_id = db
        .upsert_group(&mk_group("root", None, None))
        .expect("root");
    let srv_id = db
        .upsert_group(&mk_group("servers", Some(root_id.get_id()), None))
        .expect("servers");
    let prod_id = db
        .upsert_group(&mk_group("production", Some(srv_id.get_id()), None))
        .expect("production");

    let groups = db.list_groups().expect("list");
    assert_eq!(groups.len(), 3);

    let root = db.get_group(root_id.get_id()).expect("get").expect("some");
    assert_eq!(root.parent_id, None);

    let srv = db.get_group(srv_id.get_id()).expect("get").expect("some");
    assert_eq!(srv.parent_id, Some(root_id.get_id()));

    let prod = db.get_group(prod_id.get_id()).expect("get").expect("some");
    assert_eq!(prod.parent_id, Some(srv_id.get_id()));
}

#[test]
fn delete_group_recursively_removes_descendants_and_connections_but_not_siblings() {
    let db = repo();
    let root = db
        .upsert_group(&mk_group("root", None, None))
        .expect("root");
    let child = db
        .upsert_group(&mk_group("child", Some(root.get_id()), None))
        .expect("child");
    let grandchild = db
        .upsert_group(&mk_group("grandchild", Some(child.get_id()), None))
        .expect("grandchild");
    let sibling = db
        .upsert_group(&mk_group("sibling", None, None))
        .expect("sibling");

    let root_conn = db
        .upsert_connection(&mk_local_conn("root conn", Some(root.get_id())))
        .expect("root conn");
    let nested_conn = db
        .upsert_connection(&mk_local_conn("nested conn", Some(grandchild.get_id())))
        .expect("nested conn");
    let sibling_conn = db
        .upsert_connection(&mk_local_conn("sibling conn", Some(sibling.get_id())))
        .expect("sibling conn");

    db.delete_group(root.get_id()).expect("recursive delete");

    for id in [root.get_id(), child.get_id(), grandchild.get_id()] {
        assert_eq!(db.get_group(id).expect("get removed group"), None);
    }
    for id in [root_conn.get_id(), nested_conn.get_id()] {
        assert_eq!(db.get_connection(id).expect("get removed connection"), None);
    }
    assert!(
        db.get_group(sibling.get_id())
            .expect("get sibling")
            .is_some()
    );
    assert!(
        db.get_connection(sibling_conn.get_id())
            .expect("get sibling connection")
            .is_some()
    );
}

#[test]
fn delete_group_recursively_cleans_connection_scoped_secrets() {
    let store = Arc::new(MockStore::default());
    let db = SqliteRepository::open_in_memory()
        .expect("open in-memory DB")
        .with_credential_store(store.clone() as Arc<dyn CredentialStore>);
    let root = db
        .upsert_group(&mk_group("root", None, None))
        .expect("root");
    let child = db
        .upsert_group(&mk_group("child", Some(root.get_id()), None))
        .expect("child");
    let first = db
        .upsert_connection(&mk_local_conn("first", Some(root.get_id())))
        .expect("first");
    let second = db
        .upsert_connection(&mk_local_conn("second", Some(child.get_id())))
        .expect("second");
    let keys = [first.get_id(), second.get_id()]
        .map(|id| CredentialRef::for_connection(id, CredentialPurpose::Password));
    for (index, key) in keys.iter().enumerate() {
        store
            .store(key, &Secret::new(format!("secret-{index}").into_bytes()))
            .expect("store secret");
    }

    db.delete_group(root.get_id()).expect("recursive delete");

    for key in keys {
        assert!(store.get(&key).expect("get deleted secret").is_none());
    }
}

#[test]
fn move_group_to_different_parent() {
    let db = repo();
    let a = db.upsert_group(&mk_group("A", None, None)).expect("A");
    let b = db.upsert_group(&mk_group("B", None, None)).expect("B");
    let c = db
        .upsert_group(&mk_group("C", Some(a.get_id()), None))
        .expect("C");

    // Move C from A to B
    db.move_group(c.get_id(), Some(b.get_id()), 1)
        .expect("move");
    let moved = db.get_group(c.get_id()).expect("get").expect("some");
    assert_eq!(moved.parent_id, Some(b.get_id()));
}

// ---------------------------------------------------------------------------
// Cycle rejection — groups
// ---------------------------------------------------------------------------

#[test]
fn move_group_self_is_rejected() {
    let db = repo();
    let id = db.upsert_group(&mk_group("g", None, None)).expect("g");
    assert!(matches!(
        db.move_group(id.get_id(), Some(id.get_id()), 0),
        Err(RepositoryError::Conflict(_))
    ));
}

#[test]
fn move_group_to_descendant_is_rejected() {
    let db = repo();
    // A → B → C
    let a = db.upsert_group(&mk_group("A", None, None)).expect("A");
    let b = db
        .upsert_group(&mk_group("B", Some(a.get_id()), None))
        .expect("B");
    let c = db
        .upsert_group(&mk_group("C", Some(b.get_id()), None))
        .expect("C");

    // Try to move A under C (C is a descendant of A).
    assert!(matches!(
        db.move_group(a.get_id(), Some(c.get_id()), 0),
        Err(RepositoryError::Conflict(_))
    ));
}

#[test]
fn upsert_group_cycle_rejected() {
    let db = repo();
    let a = db.upsert_group(&mk_group("A", None, None)).expect("A");
    let b = db
        .upsert_group(&mk_group("B", Some(a.get_id()), None))
        .expect("B");

    // Try to set A's parent to B (would make A → B → A).
    let cyclic = Group {
        id: a.get_id(),
        parent_id: Some(b.get_id()),
        name: "A".to_string(),
        sort: 0,
        default_credential: None,
    };
    assert!(matches!(
        db.upsert_group(&cyclic),
        Err(RepositoryError::Conflict(_))
    ));
}

// ---------------------------------------------------------------------------
// Credential CRUD
// ---------------------------------------------------------------------------

#[test]
fn credential_insert_and_read() {
    let db = repo();
    let id = db
        .upsert_credential(&mk_cred("ssh-key", None))
        .expect("insert");
    let got = db.get_credential(id.get_id()).expect("get").expect("some");
    assert_eq!(got.name, "ssh-key");
    assert_eq!(got.kind, CredentialKind::Password);
    assert_eq!(got.username, Some("user".to_string()));
}

#[test]
fn credential_update() {
    let db = repo();
    let id = db.upsert_credential(&mk_cred("old", None)).expect("insert");
    let updated = Credential {
        id: id.get_id(),
        name: "new".to_string(),
        kind: CredentialKind::SshKey,
        folder_id: None,
        username: None,
    };
    db.upsert_credential(&updated).expect("update");
    let got = db.get_credential(id.get_id()).expect("get").expect("some");
    assert_eq!(got.name, "new");
    assert_eq!(got.kind, CredentialKind::SshKey);
    assert_eq!(got.username, None);
}

#[test]
fn credential_delete() {
    let db = repo();
    let id = db.upsert_credential(&mk_cred("tmp", None)).expect("insert");
    db.delete_credential(id.get_id()).expect("delete");
    assert!(db.get_credential(id.get_id()).expect("get").is_none());
}

// ---------------------------------------------------------------------------
// Credential sharing (one credential → many connections)
// ---------------------------------------------------------------------------

#[test]
fn credential_shared_by_multiple_connections() {
    let db = repo();
    let cred_id = db
        .upsert_credential(&mk_cred("shared", None))
        .expect("cred");

    // Two different connections reference the same credential.
    let c1 = mk_rdp_conn("server-1", None, Some(cred_id.get_id()));
    let c2 = mk_rdp_conn("server-2", None, Some(cred_id.get_id()));
    let id1 = db.upsert_connection(&c1).expect("conn1");
    let id2 = db.upsert_connection(&c2).expect("conn2");

    let got1 = db.get_connection(id1.get_id()).expect("get").expect("some");
    let got2 = db.get_connection(id2.get_id()).expect("get").expect("some");
    assert_eq!(
        got1.credential_source,
        Some(CredentialSource::Object(cred_id.get_id()))
    );
    assert_eq!(
        got2.credential_source,
        Some(CredentialSource::Object(cred_id.get_id()))
    );
}

#[test]
fn delete_credential_nullifies_connection_reference() {
    let db = repo();
    let cred_id = db.upsert_credential(&mk_cred("temp", None)).expect("cred");
    let conn = mk_rdp_conn("srv", None, Some(cred_id.get_id()));
    let cid = db.upsert_connection(&conn).expect("conn");

    db.delete_credential(cred_id.get_id()).expect("delete cred");

    let got = db.get_connection(cid.get_id()).expect("get").expect("some");
    assert_eq!(
        got.credential_source, None,
        "credential_id should be nullified"
    );
}

#[test]
fn delete_credential_nullifies_group_default() {
    let db = repo();
    let cred_id = db
        .upsert_credential(&mk_cred("default-cred", None))
        .expect("cred");
    let gid = db
        .upsert_group(&mk_group("g", None, Some(cred_id.get_id())))
        .expect("group");

    db.delete_credential(cred_id.get_id()).expect("delete cred");

    let got = db.get_group(gid.get_id()).expect("get").expect("some");
    assert_eq!(
        got.default_credential, None,
        "default_credential_id should be nullified"
    );
}

// ---------------------------------------------------------------------------
// Credential-folder CRUD & nested tree
// ---------------------------------------------------------------------------

#[test]
fn credential_folder_insert_and_read() {
    let db = repo();
    let id = db
        .upsert_credential_folder(&mk_folder("Work", None))
        .expect("insert");
    let got = db
        .get_credential_folder(id.get_id())
        .expect("get")
        .expect("some");
    assert_eq!(got.name, "Work");
    assert_eq!(got.parent_id, None);
}

#[test]
fn credential_folder_nested() {
    let db = repo();
    let root = db
        .upsert_credential_folder(&mk_folder("root", None))
        .expect("root");
    let sub = db
        .upsert_credential_folder(&mk_folder("sub", Some(root.get_id())))
        .expect("sub");

    let all = db.list_credential_folders().expect("list");
    assert_eq!(all.len(), 2);

    let got_sub = db
        .get_credential_folder(sub.get_id())
        .expect("get")
        .expect("some");
    assert_eq!(got_sub.parent_id, Some(root.get_id()));
}

#[test]
fn delete_credential_folder_blocked_when_has_sub_folders() {
    let db = repo();
    let parent = db
        .upsert_credential_folder(&mk_folder("parent", None))
        .expect("insert");
    let _child = db
        .upsert_credential_folder(&mk_folder("child", Some(parent.get_id())))
        .expect("child");

    assert!(matches!(
        db.delete_credential_folder(parent.get_id()),
        Err(RepositoryError::Conflict(_))
    ));
}

#[test]
fn delete_credential_folder_blocked_when_has_credentials() {
    let db = repo();
    let fid = db
        .upsert_credential_folder(&mk_folder("f", None))
        .expect("folder");
    let _cred = db
        .upsert_credential(&mk_cred("in-folder", Some(fid.get_id())))
        .expect("cred");

    assert!(matches!(
        db.delete_credential_folder(fid.get_id()),
        Err(RepositoryError::Conflict(_))
    ));
}

#[test]
fn delete_credential_folder_empty_ok() {
    let db = repo();
    let fid = db
        .upsert_credential_folder(&mk_folder("empty", None))
        .expect("insert");
    db.delete_credential_folder(fid.get_id()).expect("delete");
    assert!(
        db.get_credential_folder(fid.get_id())
            .expect("get")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Cycle rejection — credential folders
// ---------------------------------------------------------------------------

#[test]
fn move_folder_self_is_rejected() {
    let db = repo();
    let id = db
        .upsert_credential_folder(&mk_folder("f", None))
        .expect("insert");
    assert!(matches!(
        db.move_credential_folder(id.get_id(), Some(id.get_id()), 0),
        Err(RepositoryError::Conflict(_))
    ));
}

#[test]
fn move_folder_to_descendant_is_rejected() {
    let db = repo();
    // A → B → C
    let a = db
        .upsert_credential_folder(&mk_folder("A", None))
        .expect("A");
    let b = db
        .upsert_credential_folder(&mk_folder("B", Some(a.get_id())))
        .expect("B");
    let c = db
        .upsert_credential_folder(&mk_folder("C", Some(b.get_id())))
        .expect("C");

    // Attempt: move A under C (C is a descendant of A).
    assert!(matches!(
        db.move_credential_folder(a.get_id(), Some(c.get_id()), 0),
        Err(RepositoryError::Conflict(_))
    ));
}

// ---------------------------------------------------------------------------
// Inheritance resolution through the repository
// ---------------------------------------------------------------------------

#[test]
fn resolve_explicit_credential_on_connection() {
    let db = repo();
    let cred_id = db
        .upsert_credential(&mk_cred("explicit", None))
        .expect("cred");
    let conn = mk_rdp_conn("srv", None, Some(cred_id.get_id()));
    let cid = db.upsert_connection(&conn).expect("conn");

    let resolved = db
        .resolve_effective_credential(cid.get_id())
        .expect("resolve");
    assert_eq!(resolved, Some(cred_id.get_id()));
}

#[test]
fn resolve_inherits_from_direct_group() {
    let db = repo();
    let cred_id = db
        .upsert_credential(&mk_cred("group-cred", None))
        .expect("cred");
    let gid = db
        .upsert_group(&mk_group("g", None, Some(cred_id.get_id())))
        .expect("group");
    let conn = mk_local_conn("c", Some(gid.get_id()));
    let cid = db.upsert_connection(&conn).expect("conn");

    let resolved = db
        .resolve_effective_credential(cid.get_id())
        .expect("resolve");
    assert_eq!(resolved, Some(cred_id.get_id()));
}

#[test]
fn resolve_inherits_from_ancestor_group() {
    let db = repo();
    let cred_id = db
        .upsert_credential(&mk_cred("grandparent-cred", None))
        .expect("cred");
    // grandparent (has default_cred) → parent (none) → connection
    let grandparent = db
        .upsert_group(&mk_group("grandparent", None, Some(cred_id.get_id())))
        .expect("grandparent");
    let parent = db
        .upsert_group(&mk_group("parent", Some(grandparent.get_id()), None))
        .expect("parent");
    let conn = mk_local_conn("c", Some(parent.get_id()));
    let cid = db.upsert_connection(&conn).expect("conn");

    let resolved = db
        .resolve_effective_credential(cid.get_id())
        .expect("resolve");
    assert_eq!(resolved, Some(cred_id.get_id()));
}

#[test]
fn resolve_connection_credential_overrides_group() {
    let db = repo();
    let group_cred = db
        .upsert_credential(&mk_cred("group-cred", None))
        .expect("cred1");
    let conn_cred = db
        .upsert_credential(&mk_cred("conn-cred", None))
        .expect("cred2");
    let gid = db
        .upsert_group(&mk_group("g", None, Some(group_cred.get_id())))
        .expect("group");
    let conn = mk_rdp_conn("srv", Some(gid.get_id()), Some(conn_cred.get_id()));
    let cid = db.upsert_connection(&conn).expect("conn");

    let resolved = db
        .resolve_effective_credential(cid.get_id())
        .expect("resolve");
    assert_eq!(
        resolved,
        Some(conn_cred.get_id()),
        "connection cred wins over group cred"
    );
}

#[test]
fn resolve_nearest_ancestor_wins() {
    let db = repo();
    let far_cred = db.upsert_credential(&mk_cred("far", None)).expect("cred1");
    let near_cred = db.upsert_credential(&mk_cred("near", None)).expect("cred2");
    let grandparent = db
        .upsert_group(&mk_group("gp", None, Some(far_cred.get_id())))
        .expect("gp");
    let parent = db
        .upsert_group(&mk_group(
            "p",
            Some(grandparent.get_id()),
            Some(near_cred.get_id()),
        ))
        .expect("p");
    let conn = mk_local_conn("c", Some(parent.get_id()));
    let cid = db.upsert_connection(&conn).expect("conn");

    let resolved = db
        .resolve_effective_credential(cid.get_id())
        .expect("resolve");
    assert_eq!(resolved, Some(near_cred.get_id()), "nearer ancestor wins");
}

#[test]
fn resolve_no_credential_anywhere() {
    let db = repo();
    let gid = db.upsert_group(&mk_group("g", None, None)).expect("group");
    let cid = db
        .upsert_connection(&mk_local_conn("c", Some(gid.get_id())))
        .expect("conn");

    let resolved = db
        .resolve_effective_credential(cid.get_id())
        .expect("resolve");
    assert_eq!(resolved, None);
}

#[test]
fn resolve_returns_not_found_for_missing_connection() {
    let db = repo();
    assert!(matches!(
        db.resolve_effective_credential(ConnectionId::new(999)),
        Err(RepositoryError::NotFound)
    ));
}

// ---------------------------------------------------------------------------
// Sibling ordering
// ---------------------------------------------------------------------------

#[test]
fn connections_ordered_by_sort() {
    let db = repo();
    let gid = db.upsert_group(&mk_group("g", None, None)).expect("group");

    let mut c1 = mk_local_conn("c1", Some(gid.get_id()));
    c1.sort = 10;
    let mut c2 = mk_local_conn("c2", Some(gid.get_id()));
    c2.sort = 5;
    let mut c3 = mk_local_conn("c3", Some(gid.get_id()));
    c3.sort = 20;

    db.upsert_connection(&c1).expect("c1");
    db.upsert_connection(&c2).expect("c2");
    db.upsert_connection(&c3).expect("c3");

    let all = db.list_connections().expect("list");
    let names: Vec<_> = all.iter().map(|c| c.name.as_str()).collect();
    // Expected order: c2(5) < c1(10) < c3(20)
    assert_eq!(names, ["c2", "c1", "c3"]);
}

#[test]
fn groups_ordered_by_sort_within_parent() {
    let db = repo();
    let mut g1 = mk_group("g1", None, None);
    g1.sort = 10;
    let mut g2 = mk_group("g2", None, None);
    g2.sort = 5;
    let mut g3 = mk_group("g3", None, None);
    g3.sort = 20;

    db.upsert_group(&g1).expect("g1");
    db.upsert_group(&g2).expect("g2");
    db.upsert_group(&g3).expect("g3");

    let all = db.list_groups().expect("list");
    let names: Vec<_> = all.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["g2", "g1", "g3"]);
}

// ---------------------------------------------------------------------------
// Machine-local application state
// ---------------------------------------------------------------------------

#[test]
fn app_state_get_set_delete() {
    let db = repo();
    assert_eq!(db.get_state("active-panel").expect("get"), None);

    db.set_state("active-panel", "settings").expect("set");
    assert_eq!(
        db.get_state("active-panel").expect("get"),
        Some("settings".to_string())
    );

    // Overwrite
    db.set_state("active-panel", "connections")
        .expect("overwrite");
    assert_eq!(
        db.get_state("active-panel").expect("get"),
        Some("connections".to_string())
    );

    db.delete_state("active-panel").expect("delete");
    assert_eq!(db.get_state("active-panel").expect("get"), None);
}

// ---------------------------------------------------------------------------
// Repository is object-safe
// ---------------------------------------------------------------------------

#[test]
fn repository_is_object_safe() {
    let r: Box<dyn ConnectionRepository> = Box::new(repo());
    let gid = r.upsert_group(&mk_group("g", None, None)).expect("group");
    assert!(!gid.get_id().is_unsaved());
}

#[test]
fn app_state_repository_is_object_safe() {
    let state: Box<dyn AppStateRepository> = Box::new(repo());
    state.set_state("key", "value").expect("set");
    assert_eq!(
        state.get_state("key").expect("get").as_deref(),
        Some("value")
    );
}

// ---------------------------------------------------------------------------
// Trait-method result helpers (GroupId, ConnectionId, etc. don't have get() directly)
// ---------------------------------------------------------------------------

/// Small extension trait so tests can call `.get_id()` on the returned newtype
/// for slightly nicer ergonomics.
trait GetId {
    type Id;
    fn get_id(self) -> Self::Id;
}

impl GetId for GroupId {
    type Id = GroupId;
    fn get_id(self) -> GroupId {
        self
    }
}
impl GetId for ConnectionId {
    type Id = ConnectionId;
    fn get_id(self) -> ConnectionId {
        self
    }
}
impl GetId for CredentialId {
    type Id = CredentialId;
    fn get_id(self) -> CredentialId {
        self
    }
}
impl GetId for CredentialFolderId {
    type Id = CredentialFolderId;
    fn get_id(self) -> CredentialFolderId {
        self
    }
}
