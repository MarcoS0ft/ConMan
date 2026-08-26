//! Integration test for the RoyalTS `.rjson` importer (P9.2): round-trips the
//! checked-in sample fixture through the dialog-free
//! [`cm_storage::import::import_from_path`] seam into a real in-memory
//! [`SqliteRepository`] + a mock keychain, and asserts the resulting tree,
//! deduped credential, and plaintext secret all resolve correctly. Unit tests
//! for the parser itself (`royalts::parse`) live next to the source in
//! `cm-storage/src/import/royalts.rs`.

use std::collections::HashMap;
use std::sync::Mutex;

use cm_core::{
    ConnectionKind, ConnectionRepository, ConnectionSettings, CredentialError, CredentialRef,
    CredentialSource, CredentialStore, Secret,
};
use cm_storage::SqliteRepository;
use cm_storage::import::import_from_path;

/// Same minimal mock keychain pattern used by `tests/json_io.rs` and
/// `cm-ui`'s `import_export.rs` tests: keyed by the opaque
/// `CredentialRef` service/account pair.
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
fn royalts_fixture_round_trips_into_a_real_repo_and_keychain() {
    let repo = SqliteRepository::open_in_memory().expect("open in-memory db");
    let store = MockStore::default();
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/royalts_sample.rjson"
    );

    let outcome = import_from_path(fixture_path.as_ref(), &repo, Some(&store))
        .expect("royalts fixture should import cleanly");

    // ---- Group tree: nesting resolves through the repo -------------------
    let groups = repo.list_groups().expect("list groups");
    let prod = groups
        .iter()
        .find(|g| g.name == "Production")
        .expect("Production group persisted");
    let web = groups
        .iter()
        .find(|g| g.name == "Web Tier")
        .expect("Web Tier group persisted");
    assert_eq!(web.parent_id, Some(prod.id));
    let legacy_folder = groups
        .iter()
        .find(|g| g.name == "Legacy Family Folder")
        .expect("legacy RoyalRDS-family folder persisted");

    // ---- Credential dedupe: exactly one, shared by two connections -------
    let credentials = repo.list_credentials().expect("list credentials");
    assert_eq!(
        credentials.len(),
        1,
        "the RoyalTS credential shared by two connections must dedupe to one row"
    );
    let cred = &credentials[0];
    assert_eq!(cred.name, "shared-app-login");

    let connections = repo.list_connections().expect("list connections");
    let sharing: Vec<_> = connections
        .iter()
        .filter(|c| c.credential_source == Some(CredentialSource::Object(cred.id)))
        .collect();
    assert_eq!(
        sharing.len(),
        2,
        "both connections should resolve to the one credential"
    );

    // ---- Connections: RDP + SSH + legacy-family + port defaulting --------
    let rdp = connections
        .iter()
        .find(|c| c.name == "app-server-rdp")
        .expect("rdp connection persisted");
    assert_eq!(rdp.kind, ConnectionKind::Rdp);
    match &rdp.settings {
        ConnectionSettings::Rdp(s) => assert_eq!(s.host, "app01.internal.example"),
        other => panic!("expected Rdp settings, got {other:?}"),
    }

    let no_port_rdp = connections
        .iter()
        .find(|c| c.name == "no-port-rdp")
        .expect("port-defaulted rdp connection persisted");
    match &no_port_rdp.settings {
        ConnectionSettings::Rdp(s) => assert_eq!(s.port, 3389),
        other => panic!("expected Rdp settings, got {other:?}"),
    }

    let no_port_ssh = connections
        .iter()
        .find(|c| c.name == "no-port-ssh")
        .expect("port-defaulted ssh connection persisted");
    match &no_port_ssh.settings {
        ConnectionSettings::Ssh(s) => assert_eq!(s.port, 22),
        other => panic!("expected Ssh settings, got {other:?}"),
    }

    let telnet = connections
        .iter()
        .find(|c| c.name == "serial-console")
        .expect("Telnet connection persisted");
    assert_eq!(telnet.kind, ConnectionKind::Telnet);
    assert_eq!(telnet.credential_source, Some(CredentialSource::Prompt));
    match &telnet.settings {
        ConnectionSettings::Telnet(s) => {
            assert_eq!(s.host, "console.internal.example");
            assert_eq!(s.port, 23143);
        }
        other => panic!("expected Telnet settings, got {other:?}"),
    }

    let default_port_telnet = connections
        .iter()
        .find(|c| c.name == "default-port-telnet")
        .expect("default-port Telnet connection persisted");
    match &default_port_telnet.settings {
        ConnectionSettings::Telnet(s) => assert_eq!(s.port, 23),
        other => panic!("expected Telnet settings, got {other:?}"),
    }
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.message.contains("serial-console")),
        "ignored RoyalTS Telnet credentials must be visible to the user"
    );

    let legacy = connections
        .iter()
        .find(|c| c.name == "legacy-family-rdp")
        .expect("legacy RoyalRDS-family connection persisted");
    assert_eq!(legacy.group_id, Some(legacy_folder.id));

    // ---- Web/VNC skip: counted warning, never silent, never persisted ----
    assert!(!connections.iter().any(|c| c.name == "legacy-vnc-console"));
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.message.contains("unsupported node kind")),
        "the skipped VNC node must be a counted warning: {:?}",
        outcome.warnings
    );

    // ---- Secret: plaintext password actually resolves from the keychain --
    assert_eq!(outcome.stats.secrets_imported, 1);
    let secret = store
        .get(&CredentialRef::new(
            cred.id,
            cm_core::CredentialPurpose::Password,
        ))
        .expect("keychain lookup")
        .expect("password secret should be present");
    assert_eq!(secret.expose(), b"hunter2-plaintext");
}
