//! Integration tests for [`cm_storage::json_io`].
//!
//! Each test opens a fresh in-memory [`SqliteRepository`] so tests are fully
//! independent.  Tests cover:
//!
//! - Round-trip: export → import preserves the full tree minus secrets.
//! - Secrets excluded by default; included and transported only when gated.
//! - ID remap correctness: imported records receive fresh IDs; links are
//!   rewritten correctly.
//! - Malformed JSON handled without panic.
//! - Old / unsupported version rejected without panic.
//! - Cyclic parent references in untrusted input do not panic or loop.
//! - Empty export round-trips cleanly.

use std::collections::HashMap;
use std::sync::Mutex;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionRepository, ConnectionSettings, Credential,
    CredentialError, CredentialFolder, CredentialFolderId, CredentialId, CredentialKind,
    CredentialPurpose, CredentialRef, CredentialSource, CredentialStore, Group, GroupId,
    LocalSettings, RdpSettings, Secret, SshAuthMethod, SshSettings, TelnetSettings,
};
use cm_storage::{
    ENVELOPE_VERSION, ExportOptions, ImportExportError, ImportStats, SqliteRepository, export,
    export_to_json, import, import_from_json,
};

// ---------------------------------------------------------------------------
// Test helpers
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

fn mk_folder(name: &str, parent: Option<CredentialFolderId>) -> CredentialFolder {
    CredentialFolder {
        id: CredentialFolderId::UNSAVED,
        parent_id: parent,
        name: name.to_string(),
        sort: 0,
    }
}

fn mk_cred(name: &str, kind: CredentialKind, folder: Option<CredentialFolderId>) -> Credential {
    Credential {
        id: CredentialId::UNSAVED,
        name: name.to_string(),
        kind,
        folder_id: folder,
        username: Some("testuser".to_string()),
    }
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
        1_000,
        1_000,
    )
    .expect("mk_rdp_conn")
}

fn mk_ssh_conn(name: &str, group_id: Option<GroupId>, cred: Option<CredentialId>) -> Connection {
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_string(),
        ConnectionKind::Ssh,
        ConnectionSettings::Ssh(SshSettings {
            host: "ssh.example.com".to_string(),
            port: SshSettings::DEFAULT_PORT,
            username: "deploy".to_string(),
            auth_method: SshAuthMethod::Password,
        }),
        cred.map(CredentialSource::Object),
        0,
        2_000,
        2_000,
    )
    .expect("mk_ssh_conn")
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
    .expect("mk_local_conn")
}

fn mk_telnet_conn(name: &str, group_id: Option<GroupId>) -> Connection {
    Connection::new(
        ConnectionId::UNSAVED,
        group_id,
        name.to_string(),
        ConnectionKind::Telnet,
        ConnectionSettings::Telnet(TelnetSettings {
            host: "serial-console.example".to_string(),
            port: TelnetSettings::DEFAULT_PORT,
        }),
        Some(CredentialSource::Prompt),
        0,
        3_000,
        3_000,
    )
    .expect("mk_telnet_conn")
}

// ---------------------------------------------------------------------------
// Mock credential store for testing gated-secrets path.
// ---------------------------------------------------------------------------

/// A thread-safe in-memory credential store backed by a HashMap.
struct MockStore {
    data: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl MockStore {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }

    fn seed(&self, cred_id: CredentialId, purpose: CredentialPurpose, secret: &[u8]) {
        let key = CredentialRef::new(cred_id, purpose);
        self.data.lock().expect("lock").insert(
            (key.service().to_string(), key.account().to_string()),
            secret.to_vec(),
        );
    }

    fn get_raw(&self, cred_id: CredentialId, purpose: CredentialPurpose) -> Option<Vec<u8>> {
        let key = CredentialRef::new(cred_id, purpose);
        self.data
            .lock()
            .expect("lock")
            .get(&(key.service().to_string(), key.account().to_string()))
            .cloned()
    }
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
        let raw = data.get(&(key.service().to_string(), key.account().to_string()));
        Ok(raw.map(|v| Secret::new(v.clone())))
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
// Tests: round-trip preserves tree minus secrets
// ---------------------------------------------------------------------------

#[test]
fn round_trip_full_tree() {
    // ---- Source repo -------------------------------------------------------
    let src = repo();

    // Credential folder
    let folder_id = src
        .upsert_credential_folder(&mk_folder("Work", None))
        .expect("folder");

    // Credential inside that folder
    let cred_id = src
        .upsert_credential(&mk_cred(
            "deploy-key",
            CredentialKind::SshKey,
            Some(folder_id),
        ))
        .expect("cred");

    // Groups: Servers → Production (nested)
    let servers_id = src
        .upsert_group(&mk_group("Servers", None, Some(cred_id)))
        .expect("group-servers");
    let prod_id = src
        .upsert_group(&mk_group("Production", Some(servers_id), None))
        .expect("group-prod");

    // Connections
    let _c1 = src
        .upsert_connection(&mk_rdp_conn("rdp-host", Some(prod_id), Some(cred_id)))
        .expect("conn-rdp");
    let _c2 = src
        .upsert_connection(&mk_ssh_conn("ssh-host", Some(servers_id), None))
        .expect("conn-ssh");

    // ---- Export (no secrets) -----------------------------------------------
    let opts = ExportOptions::default();
    let envelope = export(&src, &opts, None).expect("export");

    assert_eq!(envelope.conman_export_version, ENVELOPE_VERSION);
    assert_eq!(envelope.credential_folders.len(), 1);
    assert_eq!(envelope.credentials.len(), 1);
    assert_eq!(envelope.groups.len(), 2);
    assert_eq!(envelope.connections.len(), 2);
    assert!(
        envelope.credential_secrets.is_empty(),
        "secrets excluded by default"
    );

    // ---- Import into a fresh repo ------------------------------------------
    let dst = repo();
    let stats = import(&envelope, &dst, None).expect("import");

    assert_eq!(stats.credential_folders_imported, 1);
    assert_eq!(stats.credentials_imported, 1);
    assert_eq!(stats.groups_imported, 2);
    assert_eq!(stats.connections_imported, 2);
    assert_eq!(stats.secrets_imported, 0);

    // ---- Verify structure in destination -----------------------------------
    let dst_folders = dst.list_credential_folders().expect("list folders");
    let dst_creds = dst.list_credentials().expect("list creds");
    let dst_groups = dst.list_groups().expect("list groups");
    let dst_conns = dst.list_connections().expect("list conns");

    assert_eq!(dst_folders.len(), 1);
    assert_eq!(dst_folders[0].name, "Work");
    assert_eq!(dst_folders[0].parent_id, None);

    assert_eq!(dst_creds.len(), 1);
    assert_eq!(dst_creds[0].name, "deploy-key");
    assert_eq!(dst_creds[0].kind, CredentialKind::SshKey);
    // Credential is in the imported folder.
    assert_eq!(dst_creds[0].folder_id, Some(dst_folders[0].id));

    // Two groups; find them by name.
    let dst_servers = dst_groups
        .iter()
        .find(|g| g.name == "Servers")
        .expect("Servers group");
    let dst_prod = dst_groups
        .iter()
        .find(|g| g.name == "Production")
        .expect("Production group");

    // Parent / credential links were rewritten to new IDs.
    assert_eq!(dst_servers.parent_id, None);
    assert_eq!(
        dst_servers.default_credential,
        Some(dst_creds[0].id),
        "Servers.default_credential relinked to new cred ID"
    );
    assert_eq!(
        dst_prod.parent_id,
        Some(dst_servers.id),
        "Production.parent_id relinked to new Servers ID"
    );

    // Two connections; check group linkage.
    let rdp = dst_conns
        .iter()
        .find(|c| c.name == "rdp-host")
        .expect("rdp");
    let ssh = dst_conns
        .iter()
        .find(|c| c.name == "ssh-host")
        .expect("ssh");

    assert_eq!(rdp.group_id, Some(dst_prod.id), "rdp-host in Production");
    assert_eq!(
        rdp.credential_source,
        Some(CredentialSource::Object(dst_creds[0].id)),
        "rdp-host credential relinked"
    );
    assert_eq!(ssh.group_id, Some(dst_servers.id), "ssh-host in Servers");
    assert_eq!(
        ssh.credential_source, None,
        "ssh-host has no explicit credential"
    );
}

#[test]
fn round_trip_via_json_string() {
    let src = repo();
    src.upsert_group(&mk_group("G", None, None)).expect("group");
    src.upsert_connection(&mk_local_conn("C", None))
        .expect("conn");

    let json = export_to_json(&src, &ExportOptions::default(), None).expect("export_to_json");

    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("import_from_json");

    assert_eq!(stats.groups_imported, 1);
    assert_eq!(stats.connections_imported, 1);
}

#[test]
fn telnet_round_trips_via_native_json() {
    let src = repo();
    src.upsert_connection(&mk_telnet_conn("console", None))
        .expect("insert telnet connection");

    let json = export_to_json(&src, &ExportOptions::default(), None).expect("export telnet");
    assert!(json.contains("\"telnet\""));

    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("import telnet");
    assert_eq!(stats.connections_imported, 1);
    let connections = dst.list_connections().expect("list connections");
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].kind, ConnectionKind::Telnet);
    assert_eq!(
        connections[0].credential_source,
        Some(CredentialSource::Prompt)
    );
    assert_eq!(
        connections[0].settings,
        ConnectionSettings::Telnet(TelnetSettings {
            host: "serial-console.example".to_string(),
            port: 23,
        })
    );
}

#[test]
fn round_trip_empty_repo() {
    let src = repo();
    let json = export_to_json(&src, &ExportOptions::default(), None).expect("export empty");
    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("import empty");

    assert_eq!(stats, ImportStats::default(), "empty export → empty import");
}

// ---------------------------------------------------------------------------
// Tests: secrets excluded by default + gated inclusion
// ---------------------------------------------------------------------------

#[test]
fn secrets_excluded_by_default() {
    let src = repo();
    let cred_id = src
        .upsert_credential(&mk_cred("pw", CredentialKind::Password, None))
        .expect("cred");

    // Seed a secret in a mock store.
    let store = MockStore::new();
    store.seed(cred_id, CredentialPurpose::Password, b"hunter2");

    // Export without include_secrets — even with the store provided.
    let opts = ExportOptions {
        include_secrets: false,
    };
    let envelope = export(&src, &opts, Some(&store)).expect("export");

    assert!(
        envelope.credential_secrets.is_empty(),
        "credential_secrets must be absent when include_secrets = false"
    );

    // The serialised JSON must not contain the field at all.
    let json = serde_json::to_string(&envelope).expect("to_json");
    assert!(
        !json.contains("credential_secrets"),
        "skip_serializing_if must suppress the field"
    );
}

#[test]
fn gated_secrets_export_and_import() {
    let src = repo();
    let cred_id = src
        .upsert_credential(&mk_cred("pw-cred", CredentialKind::Password, None))
        .expect("cred");

    let src_store = MockStore::new();
    src_store.seed(cred_id, CredentialPurpose::Password, b"s3cr3t!");

    // Export WITH secrets.
    let opts = ExportOptions {
        include_secrets: true,
    };
    let envelope = export(&src, &opts, Some(&src_store)).expect("export with secrets");

    assert_eq!(envelope.credential_secrets.len(), 1);
    assert_eq!(envelope.credential_secrets[0].purpose, "password");
    // Hex of b"s3cr3t!" — verify it round-trips.
    let hex: String = b"s3cr3t!".iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(envelope.credential_secrets[0].secret_hex, hex);

    // Import into a fresh repo + store.
    let dst = repo();
    let dst_store = MockStore::new();
    let stats = import(&envelope, &dst, Some(&dst_store)).expect("import with secrets");

    assert_eq!(stats.credentials_imported, 1);
    assert_eq!(
        stats.secrets_imported, 1,
        "one secret written to the keychain"
    );

    // Retrieve the new credential ID and verify the secret landed there.
    let dst_creds = dst.list_credentials().expect("list");
    assert_eq!(dst_creds.len(), 1);
    let new_cred_id = dst_creds[0].id;

    let recovered = dst_store
        .get_raw(new_cred_id, CredentialPurpose::Password)
        .expect("secret must be present under new ID");
    assert_eq!(recovered, b"s3cr3t!", "secret round-tripped correctly");
}

#[test]
fn gated_secrets_ssh_key_with_passphrase() {
    let src = repo();
    let cred_id = src
        .upsert_credential(&mk_cred(
            "key-cred",
            CredentialKind::SshKeyWithPassphrase,
            None,
        ))
        .expect("cred");

    let src_store = MockStore::new();
    src_store.seed(
        cred_id,
        CredentialPurpose::SshKey,
        b"---BEGIN PRIVATE KEY---",
    );
    src_store.seed(cred_id, CredentialPurpose::SshPassphrase, b"passphrase123");

    let opts = ExportOptions {
        include_secrets: true,
    };
    let envelope = export(&src, &opts, Some(&src_store)).expect("export");

    // Two secrets for one SshKeyWithPassphrase credential.
    assert_eq!(
        envelope.credential_secrets.len(),
        2,
        "ssh-key + ssh-passphrase"
    );

    let dst = repo();
    let dst_store = MockStore::new();
    let stats = import(&envelope, &dst, Some(&dst_store)).expect("import");

    assert_eq!(stats.secrets_imported, 2);

    let dst_creds = dst.list_credentials().expect("list");
    let new_id = dst_creds[0].id;

    assert_eq!(
        dst_store.get_raw(new_id, CredentialPurpose::SshKey),
        Some(b"---BEGIN PRIVATE KEY---".to_vec())
    );
    assert_eq!(
        dst_store.get_raw(new_id, CredentialPurpose::SshPassphrase),
        Some(b"passphrase123".to_vec())
    );
}

#[test]
fn include_secrets_without_store_gives_empty_secrets() {
    let src = repo();
    src.upsert_credential(&mk_cred("pw", CredentialKind::Password, None))
        .expect("cred");

    // include_secrets = true but no store → secrets silently omitted.
    let opts = ExportOptions {
        include_secrets: true,
    };
    let envelope = export(&src, &opts, None).expect("export");
    assert!(
        envelope.credential_secrets.is_empty(),
        "no store → no secrets"
    );
}

// ---------------------------------------------------------------------------
// Tests: ID remap correctness
// ---------------------------------------------------------------------------

#[test]
fn id_remap_group_hierarchy() {
    // src: folder → cred → (Servers(default_cred=cred) → Production(parent=Servers))
    //      connection "prod-rdp" in Production, cred=cred
    let src = repo();
    let src_cred = src
        .upsert_credential(&mk_cred("cred", CredentialKind::Password, None))
        .expect("cred");
    let src_servers = src
        .upsert_group(&mk_group("Servers", None, Some(src_cred)))
        .expect("Servers");
    let src_prod = src
        .upsert_group(&mk_group("Production", Some(src_servers), None))
        .expect("Production");
    let _conn = src
        .upsert_connection(&mk_rdp_conn("prod-rdp", Some(src_prod), Some(src_cred)))
        .expect("conn");

    let envelope = export(&src, &ExportOptions::default(), None).expect("export");

    // Pre-populate dst so that its auto-assigned IDs will differ from src.
    let dst = repo();
    {
        // Insert and delete a record to advance the row counter.
        let tmp = dst
            .upsert_group(&mk_group("_tmp", None, None))
            .expect("tmp");
        dst.delete_group(tmp).expect("del tmp");
        // Now the next INSERT will get id=2 (SQLite does not reuse row ids of
        // deleted rows when using INTEGER PRIMARY KEY without AUTOINCREMENT,
        // but it *can* reuse — however dst now has a higher rowcount, so in
        // practice after delete the next id would be max+1 = 2).
        // The test validates structural correctness regardless of exact IDs.
    }

    let stats = import(&envelope, &dst, None).expect("import");
    assert_eq!(stats.groups_imported, 2);
    assert_eq!(stats.connections_imported, 1);
    assert_eq!(stats.credentials_imported, 1);

    let dst_creds = dst.list_credentials().expect("creds");
    let dst_groups = dst.list_groups().expect("groups");
    let dst_conns = dst.list_connections().expect("conns");

    let dst_servers = dst_groups
        .iter()
        .find(|g| g.name == "Servers")
        .expect("Servers");
    let dst_prod = dst_groups
        .iter()
        .find(|g| g.name == "Production")
        .expect("Production");
    let dst_cred = &dst_creds[0];
    let dst_conn = &dst_conns[0];

    // src IDs and dst IDs are independent; only structural correctness matters.
    assert_eq!(dst_servers.parent_id, None);
    assert_eq!(dst_servers.default_credential, Some(dst_cred.id));
    assert_eq!(dst_prod.parent_id, Some(dst_servers.id));
    assert_eq!(dst_conn.group_id, Some(dst_prod.id));
    assert_eq!(
        dst_conn.credential_source,
        Some(CredentialSource::Object(dst_cred.id))
    );
}

#[test]
fn id_remap_credential_folder_hierarchy() {
    let src = repo();
    let src_root = src
        .upsert_credential_folder(&mk_folder("Root", None))
        .expect("root");
    let src_sub = src
        .upsert_credential_folder(&mk_folder("Sub", Some(src_root)))
        .expect("sub");
    let _cred = src
        .upsert_credential(&mk_cred("c", CredentialKind::Password, Some(src_sub)))
        .expect("cred");

    let envelope = export(&src, &ExportOptions::default(), None).expect("export");
    let dst = repo();
    let stats = import(&envelope, &dst, None).expect("import");

    assert_eq!(stats.credential_folders_imported, 2);
    assert_eq!(stats.credentials_imported, 1);

    let dst_folders = dst.list_credential_folders().expect("folders");
    let dst_creds = dst.list_credentials().expect("creds");

    let dst_root = dst_folders.iter().find(|f| f.name == "Root").expect("Root");
    let dst_sub = dst_folders.iter().find(|f| f.name == "Sub").expect("Sub");

    assert_eq!(dst_root.parent_id, None);
    assert_eq!(dst_sub.parent_id, Some(dst_root.id));
    assert_eq!(dst_creds[0].folder_id, Some(dst_sub.id));
}

// ---------------------------------------------------------------------------
// Tests: malformed / old-version input handled without panic
// ---------------------------------------------------------------------------

#[test]
fn malformed_json_returns_error_no_panic() {
    let dst = repo();
    let result = import_from_json("{not valid json", &dst, None);
    assert!(
        matches!(result, Err(ImportExportError::Json(_))),
        "expected Json error, got: {result:?}"
    );
}

#[test]
fn empty_input_returns_malformed_error() {
    let dst = repo();
    let result = import_from_json("", &dst, None);
    assert!(
        matches!(result, Err(ImportExportError::Malformed(_))),
        "expected Malformed error, got: {result:?}"
    );
}

#[test]
fn whitespace_only_input_returns_malformed_error() {
    let dst = repo();
    let result = import_from_json("   \t\n  ", &dst, None);
    assert!(
        matches!(result, Err(ImportExportError::Malformed(_))),
        "expected Malformed error"
    );
}

#[test]
fn unsupported_version_too_high() {
    let dst = repo();
    let json = serde_json::json!({
        "conman_export_version": 999,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": [],
        "connections": []
    })
    .to_string();

    let result = import_from_json(&json, &dst, None);
    assert!(
        matches!(
            result,
            Err(ImportExportError::UnsupportedVersion {
                found: 999,
                supported: ENVELOPE_VERSION
            })
        ),
        "got: {result:?}"
    );
}

#[test]
fn unsupported_version_zero() {
    let dst = repo();
    let json = serde_json::json!({
        "conman_export_version": 0,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": [],
        "connections": []
    })
    .to_string();

    let result = import_from_json(&json, &dst, None);
    assert!(
        matches!(
            result,
            Err(ImportExportError::UnsupportedVersion { found: 0, .. })
        ),
        "got: {result:?}"
    );
}

#[test]
fn missing_required_field_returns_json_error() {
    let dst = repo();
    // "connections" key missing.
    let json = serde_json::json!({
        "conman_export_version": 1,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": []
        // "connections" is absent — serde should error
    })
    .to_string();

    let result = import_from_json(&json, &dst, None);
    assert!(
        matches!(result, Err(ImportExportError::Json(_))),
        "expected Json error for missing field, got: {result:?}"
    );
}

#[test]
fn unknown_connection_kind_returns_json_error() {
    let dst = repo();
    // "kind" has an unrecognised value.
    let json = r#"{
        "conman_export_version": 1,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": [],
        "connections": [{
            "id": 1, "group_id": null,
            "name": "bad",
            "kind": "telepathy",
            "settings": {"rdp": {"host": "x", "port": 3389, "domain": null, "username": null}},
            "credential": null,
            "sort": 0, "created_at": 0, "updated_at": 0
        }]
    }"#;

    let result = import_from_json(json, &dst, None);
    assert!(
        matches!(result, Err(ImportExportError::Json(_))),
        "expected Json error for unknown kind, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Tests: cyclic import data does not panic
// ---------------------------------------------------------------------------

#[test]
fn cyclic_group_parent_does_not_panic() {
    // Two groups forming a cycle: A.parent = B, B.parent = A.
    let json = serde_json::json!({
        "conman_export_version": 1,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": [
            { "id": 1, "parent_id": 2, "name": "A", "sort": 0, "default_credential": null },
            { "id": 2, "parent_id": 1, "name": "B", "sort": 0, "default_credential": null }
        ],
        "connections": []
    })
    .to_string();

    let dst = repo();
    // Must not panic; must either succeed (cycle broken) or return a structured error.
    let result = import_from_json(&json, &dst, None);
    assert!(
        result.is_ok(),
        "cyclic groups should be imported (cycle broken), got: {result:?}"
    );

    let stats = result.unwrap();
    assert_eq!(
        stats.groups_imported, 2,
        "both groups imported despite cycle"
    );
}

#[test]
fn cyclic_folder_parent_does_not_panic() {
    let json = serde_json::json!({
        "conman_export_version": 1,
        "exported_at": 0,
        "credential_folders": [
            { "id": 10, "parent_id": 11, "name": "X", "sort": 0 },
            { "id": 11, "parent_id": 10, "name": "Y", "sort": 0 }
        ],
        "credentials": [],
        "groups": [],
        "connections": []
    })
    .to_string();

    let dst = repo();
    let result = import_from_json(&json, &dst, None);
    assert!(
        result.is_ok(),
        "cyclic folders should be imported (cycle broken), got: {result:?}"
    );
    assert_eq!(result.unwrap().credential_folders_imported, 2);
}

#[test]
fn self_referential_group_parent_does_not_panic() {
    // A group that is its own parent.
    let json = serde_json::json!({
        "conman_export_version": 1,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": [
            { "id": 1, "parent_id": 1, "name": "SelfRef", "sort": 0, "default_credential": null }
        ],
        "connections": []
    })
    .to_string();

    let dst = repo();
    let result = import_from_json(&json, &dst, None);
    assert!(
        result.is_ok(),
        "self-referential group must not panic: {result:?}"
    );
    assert_eq!(result.unwrap().groups_imported, 1);
}

// ---------------------------------------------------------------------------
// Tests: dangling links are silently set to None
// ---------------------------------------------------------------------------

#[test]
fn dangling_group_parent_becomes_root() {
    // Connection references a group_id=99 that does not exist in the envelope.
    let json = serde_json::json!({
        "conman_export_version": 1,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": [
            { "id": 1, "parent_id": 99, "name": "Orphan", "sort": 0, "default_credential": null }
        ],
        "connections": []
    })
    .to_string();

    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("import");
    assert_eq!(stats.groups_imported, 1);

    // The orphaned group should be inserted at root level.
    let groups = dst.list_groups().expect("list");
    assert_eq!(groups[0].name, "Orphan");
    assert_eq!(groups[0].parent_id, None, "dangling parent → root");
}

#[test]
fn dangling_credential_reference_becomes_none() {
    // Connection references credential_id=42 which is not in the envelope.
    let json = serde_json::json!({
        "conman_export_version": 1,
        "exported_at": 0,
        "credential_folders": [],
        "credentials": [],
        "groups": [],
        "connections": [{
            "id": 1,
            "group_id": null,
            "name": "no-cred",
            "kind": "local",
            "settings": {"local": {"program": null, "args": [], "working_dir": null, "env": []}},
            "credential": 42,
            "sort": 0,
            "created_at": 0,
            "updated_at": 0
        }]
    })
    .to_string();

    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("import");
    assert_eq!(stats.connections_imported, 1);

    let conns = dst.list_connections().expect("list");
    assert_eq!(
        conns[0].credential_source, None,
        "dangling credential ref → None"
    );
}

// ---------------------------------------------------------------------------
// Tests: additive semantics (import does not clobber existing data)
// ---------------------------------------------------------------------------

#[test]
fn import_is_additive() {
    let db = repo();

    // Pre-existing data.
    let existing_group = db
        .upsert_group(&mk_group("Existing", None, None))
        .expect("existing");
    let _existing_conn = db
        .upsert_connection(&mk_local_conn("existing-conn", Some(existing_group)))
        .expect("existing conn");

    // Now export a different repo and import into db.
    let src = repo();
    src.upsert_group(&mk_group("Imported", None, None))
        .expect("src group");

    let json = export_to_json(&src, &ExportOptions::default(), None).expect("export");
    import_from_json(&json, &db, None).expect("import");

    // Both the pre-existing and the imported data should coexist.
    let groups = db.list_groups().expect("list groups");
    let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
    assert!(
        names.contains(&"Existing"),
        "pre-existing group must remain"
    );
    assert!(names.contains(&"Imported"), "imported group must be added");
    assert_eq!(groups.len(), 2, "exactly two groups");

    let conns = db.list_connections().expect("list conns");
    assert_eq!(conns.len(), 1, "only the pre-existing connection");
}

// ---------------------------------------------------------------------------
// Tests: envelope schema fields
// ---------------------------------------------------------------------------

#[test]
fn exported_at_is_nonzero() {
    let src = repo();
    let envelope = export(&src, &ExportOptions::default(), None).expect("export");
    assert!(
        envelope.exported_at > 0,
        "exported_at should be a valid epoch timestamp"
    );
}

#[test]
fn envelope_version_constant_matches_serialised() {
    let src = repo();
    let json = export_to_json(&src, &ExportOptions::default(), None).expect("export_to_json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(
        parsed["conman_export_version"].as_u64().expect("u64"),
        u64::from(ENVELOPE_VERSION)
    );
}

// ---------------------------------------------------------------------------
// Tests: v2 settings travel in the envelope
// ---------------------------------------------------------------------------

#[test]
fn settings_exported_and_reimported() {
    let src = repo();
    src.set_setting("ui.theme_mode", "1").expect("set theme");
    src.set_setting("ui.density", "1").expect("set density");
    src.set_setting("terminal.font_size", "14")
        .expect("set font size");

    let envelope = export(&src, &ExportOptions::default(), None).expect("export");
    // Exported as ordered [key, value] pairs.
    assert!(
        envelope
            .settings
            .iter()
            .any(|(k, v)| k == "terminal.font_size" && v == "14"),
        "a normal (non-excluded) setting must be exported"
    );
    assert_eq!(envelope.settings.len(), 3, "all three settings exported");

    // Round-trip into a fresh repo.
    let dst = repo();
    let stats = import(&envelope, &dst, None).expect("import");
    assert_eq!(stats.settings_imported, 3);

    assert_eq!(
        dst.get_setting("ui.theme_mode").unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(dst.get_setting("ui.density").unwrap().as_deref(), Some("1"));
    assert_eq!(
        dst.get_setting("terminal.font_size").unwrap().as_deref(),
        Some("14")
    );
}

#[test]
fn excluded_settings_keys_are_not_exported() {
    let src = repo();
    // Volatile / machine-specific keys that must NOT travel.
    src.set_setting("ui.session_tabs", "{\"tabs\":[]}")
        .expect("set tabs");
    src.set_setting("app.first_run_seeded", "1")
        .expect("set seeded");
    // Machine hardware-capability cache (P7.1 cont.) — must NOT travel: a
    // pinned "accelerated" imported on a GPU-less machine would crash it.
    src.set_setting("render.backend", "accelerated")
        .expect("set render backend");
    // Agent-mode automation posture (P8.6) — must NOT travel: a DB copy must
    // never silently arrive with automation already enabled/scoped.
    src.set_setting("automation.enabled", "1")
        .expect("set automation enabled");
    src.set_setting("automation.scopes", "read,write,execute")
        .expect("set automation scopes");
    // A normal key that SHOULD travel.
    src.set_setting("ui.theme_mode", "0").expect("set theme");

    let envelope = export(&src, &ExportOptions::default(), None).expect("export");

    let keys: Vec<&str> = envelope.settings.iter().map(|(k, _)| k.as_str()).collect();
    assert!(
        !keys.contains(&"ui.session_tabs"),
        "ui.session_tabs must be excluded"
    );
    assert!(
        !keys.contains(&"app.first_run_seeded"),
        "app.first_run_seeded must be excluded"
    );
    assert!(
        !keys.contains(&"render.backend"),
        "render.backend must be excluded — it is machine-specific hardware \
         capability, and the importing machine must re-probe"
    );
    assert!(
        !keys.contains(&"automation.enabled"),
        "automation.enabled must be excluded — per-machine security posture"
    );
    assert!(
        !keys.contains(&"automation.scopes"),
        "automation.scopes must be excluded — per-machine security posture"
    );
    assert!(keys.contains(&"ui.theme_mode"), "normal key must be kept");

    // The serialised JSON must not mention the excluded keys at all.
    let json = serde_json::to_string(&envelope).expect("to_json");
    assert!(!json.contains("session_tabs"));
    assert!(!json.contains("first_run_seeded"));
    assert!(!json.contains("render.backend"));
    assert!(!json.contains("\"accelerated\""));
    assert!(!json.contains("automation.enabled"));
    assert!(!json.contains("automation.scopes"));
}

#[test]
fn empty_settings_field_is_suppressed_in_json() {
    let src = repo();
    let json = export_to_json(&src, &ExportOptions::default(), None).expect("export");
    assert!(
        !json.contains("\"settings\""),
        "empty settings list must be omitted from serialisation"
    );
}

#[test]
fn v1_envelope_without_settings_still_imports() {
    // A hand-written v1 envelope (no `settings` field) must import cleanly for
    // backward compatibility.
    let json = serde_json::json!({
        "conman_export_version": 1,
        "exported_at": 123,
        "credential_folders": [],
        "credentials": [],
        "groups": [
            { "id": 1, "parent_id": null, "name": "G", "sort": 0, "default_credential": null }
        ],
        "connections": []
    })
    .to_string();

    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("v1 import must succeed");
    assert_eq!(stats.groups_imported, 1);
    assert_eq!(stats.settings_imported, 0, "v1 carries no settings");
}

#[test]
fn v2_envelope_with_settings_imports() {
    // A hand-written v2 envelope with a settings list.
    let json = serde_json::json!({
        "conman_export_version": 2,
        "exported_at": 123,
        "credential_folders": [],
        "credentials": [],
        "groups": [],
        "connections": [],
        "settings": [["terminal.font_size", "16"], ["ui.theme_mode", "1"]]
    })
    .to_string();

    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("v2 import");
    assert_eq!(stats.settings_imported, 2);
    assert_eq!(
        dst.get_setting("terminal.font_size").unwrap().as_deref(),
        Some("16")
    );
}

#[test]
fn v2_envelope_with_render_backend_is_skipped_on_import() {
    // Defense in depth: even a hand-edited / untrusted envelope that carries
    // the excluded `render.backend` key must NOT have it applied on import —
    // mirrors the defensive re-filter in `import()` (P7.1 cont.).
    let json = serde_json::json!({
        "conman_export_version": 2,
        "exported_at": 123,
        "credential_folders": [],
        "credentials": [],
        "groups": [],
        "connections": [],
        "settings": [["render.backend", "accelerated"], ["ui.theme_mode", "1"]]
    })
    .to_string();

    let dst = repo();
    let stats = import_from_json(&json, &dst, None).expect("v2 import");
    assert_eq!(
        stats.settings_imported, 1,
        "only the non-excluded key is counted"
    );
    assert_eq!(
        dst.get_setting("render.backend").unwrap(),
        None,
        "render.backend must not be applied even if present in the input"
    );
    assert_eq!(
        dst.get_setting("ui.theme_mode").unwrap().as_deref(),
        Some("1")
    );
}
