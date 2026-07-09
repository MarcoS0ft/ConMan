//! Integration test for the CSV importer (P9.3): round-trips the checked-in
//! sample fixture through the dialog-free
//! [`cm_storage::import::import_from_path`] seam into a real in-memory
//! [`SqliteRepository`] + a mock keychain, and asserts the resulting tree,
//! deduped credential, and SSH-key secret all resolve correctly. Unit tests
//! for the parser itself (`csv::parse`) live next to the source in
//! `cm-storage/src/import/csv.rs`.

use std::collections::HashMap;
use std::sync::Mutex;

use cm_core::{
    ConnectionKind, ConnectionRepository, ConnectionSettings, CredentialError, CredentialRef,
    CredentialSource, CredentialStore, Secret, SshAuthMethod,
};
use cm_storage::SqliteRepository;
use cm_storage::import::import_from_path;

/// Same minimal mock keychain pattern used by `tests/import_royalts.rs`.
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

#[test]
fn csv_fixture_round_trips_into_a_real_repo_and_keychain() {
    let repo = SqliteRepository::open_in_memory().expect("open in-memory db");
    let store = MockStore::default();
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/csv_sample.csv");

    let outcome = import_from_path(fixture_path.as_ref(), &repo, Some(&store))
        .expect("csv fixture should import cleanly");

    // ---- Group tree: group_path nesting resolves through the repo --------
    let groups = repo.list_groups().expect("list groups");
    let prod = groups
        .iter()
        .find(|g| g.name == "Prod")
        .expect("Prod group persisted");
    let web = groups
        .iter()
        .find(|g| g.name == "Web")
        .expect("Web group persisted");
    assert_eq!(web.parent_id, Some(prod.id));

    // ---- Connections: ssh + rdp + local -----------------------------------
    let connections = repo.list_connections().expect("list connections");
    let ssh = connections
        .iter()
        .find(|c| c.name == "web-01-ssh")
        .expect("ssh connection persisted");
    assert_eq!(ssh.kind, ConnectionKind::Ssh);
    match &ssh.settings {
        ConnectionSettings::Ssh(s) => {
            assert_eq!(s.host, "web01.example.test");
            assert_eq!(s.port, 22, "blank port should default to 22");
        }
        other => panic!("expected Ssh settings, got {other:?}"),
    }

    let rdp = connections
        .iter()
        .find(|c| c.name == "win-01-rdp")
        .expect("rdp connection persisted");
    match &rdp.settings {
        ConnectionSettings::Rdp(s) => {
            assert_eq!(s.host, "win01.example.test");
            assert_eq!(s.port, 3389, "blank port should default to 3389");
            assert_eq!(s.width, 1920);
            assert_eq!(s.height, 1080);
        }
        other => panic!("expected Rdp settings, got {other:?}"),
    }

    let local = connections
        .iter()
        .find(|c| c.name == "scratch-shell")
        .expect("local connection persisted");
    assert_eq!(local.kind, ConnectionKind::LocalTerminal);
    assert_eq!(
        local.credential_source, None,
        "local rows never get a credential"
    );

    // ---- Malformed row: missing host is skipped, never silently ----------
    assert!(!connections.iter().any(|c| c.name == "no-host-ssh"));
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.message.contains("missing 'host'")),
        "the skipped row must be a counted warning: {:?}",
        outcome.warnings
    );

    // ---- Shared cred_name: dedupes to one credential ----------------------
    let credentials = repo.list_credentials().expect("list credentials");
    let shared_cred = credentials
        .iter()
        .find(|c| c.name == "shared-svc")
        .expect("shared-svc credential persisted");
    let sharing: Vec<_> = connections
        .iter()
        .filter(|c| c.credential_source == Some(CredentialSource::Object(shared_cred.id)))
        .collect();
    assert_eq!(
        sharing.len(),
        2,
        "svc-a and svc-b should both resolve to the one deduped credential"
    );

    // ---- SSH key row: the private key actually resolves from the keychain
    let keyed = connections
        .iter()
        .find(|c| c.name == "build-box-key")
        .expect("key-auth connection persisted");
    match &keyed.settings {
        ConnectionSettings::Ssh(s) => {
            assert!(matches!(s.auth_method, SshAuthMethod::PublicKey { .. }))
        }
        other => panic!("expected Ssh settings, got {other:?}"),
    }
    let key_cred_id = match &keyed.credential_source {
        Some(CredentialSource::Object(id)) => *id,
        other => panic!("expected an Object credential source, got {other:?}"),
    };
    let key_secret = store
        .get(&CredentialRef::new(
            key_cred_id,
            cm_core::CredentialPurpose::SshKey,
        ))
        .expect("keychain lookup")
        .expect("ssh key secret should be present");
    assert!(
        String::from_utf8(key_secret.expose().to_vec())
            .unwrap()
            .contains("BEGIN OPENSSH PRIVATE KEY"),
        "the imported key material should round-trip byte-for-byte"
    );

    // ---- Password secret also resolves (per-row credential, no cred_name) -
    let web_conn_cred_id = match &ssh.credential_source {
        Some(CredentialSource::Object(id)) => *id,
        other => panic!("expected an Object credential source, got {other:?}"),
    };
    let password_secret = store
        .get(&CredentialRef::new(
            web_conn_cred_id,
            cm_core::CredentialPurpose::Password,
        ))
        .expect("keychain lookup")
        .expect("password secret should be present");
    assert_eq!(password_secret.expose(), b"dummy-pw-1");

    assert!(outcome.stats.secrets_imported >= 3, "{:?}", outcome.stats);
}

#[test]
fn json_extension_still_works_after_csv_registration() {
    // Regression: registering `.csv` in the dispatch table must not disturb
    // the existing native `.json` import path.
    use cm_core::{
        Connection, ConnectionId, ConnectionKind as Kind, ConnectionSettings as Settings,
        Credential, CredentialId, CredentialKind, Group, GroupId, LocalSettings,
    };

    let src_repo = SqliteRepository::open_in_memory().expect("open src db");
    let group_id = src_repo
        .upsert_group(&Group {
            id: GroupId::UNSAVED,
            parent_id: None,
            name: "prod".to_string(),
            sort: 0,
            default_credential: None,
        })
        .expect("upsert group");
    let cred_id = src_repo
        .upsert_credential(&Credential {
            id: CredentialId::UNSAVED,
            folder_id: None,
            name: "prod-cred".to_string(),
            kind: CredentialKind::Password,
            username: Some("root".to_string()),
        })
        .expect("upsert credential");
    let conn = Connection::new(
        ConnectionId::UNSAVED,
        Some(group_id),
        "web-01".to_string(),
        Kind::LocalTerminal,
        Settings::Local(LocalSettings::default()),
        Some(CredentialSource::Object(cred_id)),
        0,
        0,
        0,
    )
    .expect("build connection");
    src_repo
        .upsert_connection(&conn)
        .expect("upsert connection");

    let json = cm_storage::export_to_json(&src_repo, &cm_storage::ExportOptions::default(), None)
        .expect("export");
    let dir = tempfile::tempdir().expect("tmp dir");
    let path = dir.path().join("export.json");
    std::fs::write(&path, json).expect("write export");

    let dst_repo = SqliteRepository::open_in_memory().expect("open dst db");
    let outcome = import_from_path(&path, &dst_repo, None).expect("json import should succeed");
    assert_eq!(outcome.stats.connections_imported, 1);
}
