//! Integration test for the mRemoteNG importer (P9.4): round-trips the
//! checked-in sample fixture through the dialog-free
//! [`cm_storage::import::import_from_path`] seam into a real in-memory
//! [`SqliteRepository`] + a mock keychain, and asserts the resulting tree,
//! decrypted password, and inheritance all resolve correctly. Also exercises
//! the password-required / password-aware-retry flow for a custom-password
//! file. Unit tests for the parser itself (`mremoteng::parse`) and the
//! decryption scheme (`mremoteng_crypto`) live next to the source in
//! `cm-storage/src/import/{mremoteng,mremoteng_crypto}.rs`.

use std::collections::HashMap;
use std::sync::Mutex;

use cm_core::{
    ConnectionKind, ConnectionRepository, ConnectionSettings, CredentialError, CredentialPurpose,
    CredentialRef, CredentialSource, CredentialStore, Secret, resolve_connection_auth,
};
use cm_storage::SqliteRepository;
use cm_storage::import::import_from_path;
use cm_storage::json_io::ImportExportError;

/// Same minimal mock keychain pattern used by `tests/import_csv.rs` /
/// `tests/import_royalts.rs`.
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
fn mremoteng_fixture_round_trips_into_a_real_repo_and_keychain() {
    let repo = SqliteRepository::open_in_memory().expect("open in-memory db");
    let store = MockStore::default();
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mremoteng_confCons.xml"
    );

    // `import_from_path` (no explicit password) tries the mRemoteNG default
    // (`mR3m`), which is what this fixture is encrypted with.
    let outcome = import_from_path(fixture_path.as_ref(), &repo, Some(&store))
        .expect("mremoteng fixture should import cleanly with the default password");

    // ---- Group tree: container nesting ------------------------------------
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

    // ---- Connections: RDP + SSH2 -------------------------------------------
    let connections = repo.list_connections().expect("list connections");
    let rdp = connections
        .iter()
        .find(|c| c.name == "app01-rdp")
        .expect("rdp connection persisted");
    assert_eq!(rdp.kind, ConnectionKind::Rdp);
    match &rdp.settings {
        ConnectionSettings::Rdp(s) => assert_eq!(s.host, "app01.example.test"),
        other => panic!("expected Rdp settings, got {other:?}"),
    }
    let ssh = connections
        .iter()
        .find(|c| c.name == "app01-ssh")
        .expect("ssh connection persisted");
    assert_eq!(ssh.kind, ConnectionKind::Ssh);

    // ---- P9.6 decision 5: mRemoteNG's per-node password imports as Inline,
    // never a synthesized credential object, and resolves end-to-end through
    // `resolve_connection_auth` (username + secret) exactly like an Object
    // credential would. --------------------------------------------------
    assert!(
        repo.list_credentials()
            .expect("list credentials")
            .is_empty(),
        "mRemoteNG must never synthesize a shared credential object"
    );
    let group_list = repo.list_groups().expect("list groups");
    let cred_list = repo.list_credentials().expect("list credentials");
    assert!(matches!(
        &rdp.credential_source,
        Some(CredentialSource::Inline {
            has_secret: true,
            ..
        })
    ));
    let rdp_auth = resolve_connection_auth(
        rdp,
        &group_list,
        &cred_list,
        &store,
        CredentialPurpose::Password,
    )
    .expect("resolve rdp auth");
    assert_eq!(rdp_auth.username, "admin");
    assert_eq!(
        rdp_auth
            .secret
            .expect("rdp inline secret resolved")
            .expose(),
        b"dummy-pw-1"
    );

    // ---- Inherited password also resolves via the same Inline path ---------
    let inherited = connections
        .iter()
        .find(|c| c.name == "inherited-conn")
        .expect("inherited-conn persisted");
    assert!(matches!(
        &inherited.credential_source,
        Some(CredentialSource::Inline {
            has_secret: true,
            ..
        })
    ));
    let inherited_auth = resolve_connection_auth(
        inherited,
        &group_list,
        &cred_list,
        &store,
        CredentialPurpose::Password,
    )
    .expect("resolve inherited auth");
    assert_eq!(
        inherited_auth
            .secret
            .expect("inherited inline secret resolved")
            .expose(),
        b"dummy-shared-pw"
    );

    // ---- Unsupported protocol + blank-host: skipped, counted warnings ------
    assert!(!connections.iter().any(|c| c.name == "legacy-vnc"));
    assert!(!connections.iter().any(|c| c.name == "no-host-conn"));
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.message.contains("unsupported protocol 'VNC'")),
        "the VNC node must be a counted warning: {:?}",
        outcome.warnings
    );
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.message.contains("missing host")),
        "the hostless node must be a counted warning: {:?}",
        outcome.warnings
    );

    assert_eq!(outcome.stats.secrets_imported, 3, "{:?}", outcome.stats);
}

#[test]
fn custom_password_file_requires_password_then_succeeds_with_it() {
    use cm_storage::import::import_from_path_with_password;

    // A minimal confCons.xml encrypted with a custom (non-`mR3m`) password —
    // the canary and one connection's Password, both freshly encrypted for
    // this test (dummy host/secret, no real infra).
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections"
    EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000"
    FullFileEncryption="false"
    Protected="fn+TLW+HlsBVdm5UF1N5J++1C/cc4xLa4ayBYCR49uCa45xLKeK0ChU1M4++T6yaFfRG1nq2JoahRULTMkrB"
    ConfVersion="2.6">
  <Node Name="custom-pw-conn" Type="Connection" Protocol="SSH2"
      Hostname="custom.example.test" Username="svc"
      Password="Mgr1rTSfK8KlOpiVc0tDB8WUnd5dNg33VZDo7BmMoNkIR+nkTFAQZnuBU+NE42prNvsZCQGYM3dqHFiTug==" />
</mrng:Connections>
"#;

    let dir = tempfile::tempdir().expect("tmp dir");
    let path = dir.path().join("custom.xml");
    std::fs::write(&path, xml).expect("write fixture");

    let repo = SqliteRepository::open_in_memory().expect("open in-memory db");
    let store = MockStore::default();

    // Default password fails — the caller must be told to prompt.
    let err = import_from_path(&path, &repo, Some(&store)).expect_err("default password must fail");
    assert!(matches!(err, ImportExportError::PasswordRequired));

    // Same file, right password: succeeds.
    let outcome = import_from_path_with_password(&path, &repo, Some(&store), "custom-pw-xyz")
        .expect("the correct custom password must succeed");
    let connections = repo.list_connections().expect("list connections");
    let conn = connections
        .iter()
        .find(|c| c.name == "custom-pw-conn")
        .expect("custom-pw-conn persisted");
    assert!(matches!(
        &conn.credential_source,
        Some(CredentialSource::Inline {
            has_secret: true,
            ..
        })
    ));
    let auth = resolve_connection_auth(
        conn,
        &repo.list_groups().expect("list groups"),
        &repo.list_credentials().expect("list credentials"),
        &store,
        CredentialPurpose::Password,
    )
    .expect("resolve auth");
    assert_eq!(
        auth.secret
            .expect("custom-password inline secret resolved")
            .expose(),
        b"custom-secret"
    );
    assert_eq!(outcome.stats.secrets_imported, 1);
}

#[test]
fn json_rjson_and_csv_imports_still_work_after_xml_registration() {
    // Regression: registering `.xml` (and `PasswordRequired`) must not
    // disturb the other importers. `.json`/`.rjson`/`.csv` each already have
    // their own dedicated regression tests; this just re-confirms `.json`
    // (the simplest) still round-trips through the same `import_from_path`
    // entry point `.xml` now shares.
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
