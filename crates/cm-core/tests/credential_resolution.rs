//! Credential-resolution unit suite (P9.6-A Decision 3) — the headline
//! deliverable of this phase. `cm_core::resolve_connection_auth` is the pure
//! function `cm_ui::controller::sessions::resolve_ssh_auth`/`resolve_rdp_auth`
//! will become thin adapters over (Phase C); this suite is what the recent
//! empty-username/empty-credential bugs exposed as a real gap — every
//! `CredentialSource` arm, crossed with {secret present / absent / keychain
//! miss}, plus the exact username precedence
//! (inline > object's own username > the connection's settings username)
//! that class of bug hit.

use std::collections::HashMap;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialError,
    CredentialId, CredentialKind, CredentialPurpose, CredentialRef, CredentialSource, Group,
    GroupId, LocalSettings, RdpSettings, Secret, SshAuthMethod, SshSettings,
    resolve_connection_auth,
};

// ---------------------------------------------------------------------------
// Mock CredentialStore (mirrors cm-ui's controller/sessions.rs test helper)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockCredentialStore {
    entries: HashMap<(String, String), Secret>,
    error_key: Option<(String, String)>,
}

impl MockCredentialStore {
    fn new() -> Self {
        Self::default()
    }

    fn with_ref(mut self, r: &CredentialRef, secret: &str) -> Self {
        self.entries.insert(
            (r.service().to_owned(), r.account().to_owned()),
            Secret::from_string(secret.to_owned()),
        );
        self
    }

    fn with_object(self, id: CredentialId, purpose: CredentialPurpose, secret: &str) -> Self {
        let r = CredentialRef::new(id, purpose);
        self.with_ref(&r, secret)
    }

    fn with_connection(self, id: ConnectionId, purpose: CredentialPurpose, secret: &str) -> Self {
        let r = CredentialRef::for_connection(id, purpose);
        self.with_ref(&r, secret)
    }

    fn failing_object(mut self, id: CredentialId, purpose: CredentialPurpose) -> Self {
        let r = CredentialRef::new(id, purpose);
        self.error_key = Some((r.service().to_owned(), r.account().to_owned()));
        self
    }
}

impl cm_core::CredentialStore for MockCredentialStore {
    fn store(&self, _key: &CredentialRef, _secret: &Secret) -> Result<(), CredentialError> {
        unimplemented!("not exercised by these tests")
    }

    fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
        let k = (key.service().to_owned(), key.account().to_owned());
        if self.error_key.as_ref() == Some(&k) {
            return Err(CredentialError::Backend(
                "simulated backend failure".to_owned(),
            ));
        }
        Ok(self.entries.get(&k).cloned())
    }

    fn delete(&self, _key: &CredentialRef) -> Result<(), CredentialError> {
        unimplemented!("not exercised by these tests")
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn rdp_conn(
    id: i64,
    group_id: Option<i64>,
    credential_source: Option<CredentialSource>,
    settings_username: Option<&str>,
    settings_domain: Option<&str>,
) -> Connection {
    Connection::new(
        ConnectionId::new(id),
        group_id.map(GroupId::new),
        "rdp-conn".to_string(),
        ConnectionKind::Rdp,
        ConnectionSettings::Rdp(RdpSettings {
            host: "host.example.test".to_string(),
            port: RdpSettings::DEFAULT_PORT,
            domain: settings_domain.map(str::to_string),
            username: settings_username.map(str::to_string),
            ..RdpSettings::default()
        }),
        credential_source,
        0,
        0,
        0,
    )
    .expect("build rdp connection")
}

fn ssh_conn(
    id: i64,
    group_id: Option<i64>,
    credential_source: Option<CredentialSource>,
    settings_username: &str,
) -> Connection {
    Connection::new(
        ConnectionId::new(id),
        group_id.map(GroupId::new),
        "ssh-conn".to_string(),
        ConnectionKind::Ssh,
        ConnectionSettings::Ssh(SshSettings {
            host: "host.example.test".to_string(),
            port: SshSettings::DEFAULT_PORT,
            username: settings_username.to_string(),
            auth_method: SshAuthMethod::Password,
        }),
        credential_source,
        0,
        0,
        0,
    )
    .expect("build ssh connection")
}

fn local_conn(id: i64, credential_source: Option<CredentialSource>) -> Connection {
    Connection::new(
        ConnectionId::new(id),
        None,
        "local-conn".to_string(),
        ConnectionKind::LocalTerminal,
        ConnectionSettings::Local(LocalSettings::default()),
        credential_source,
        0,
        0,
        0,
    )
    .expect("build local connection")
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

fn make_credential(id: i64, username: Option<&str>) -> Credential {
    Credential {
        id: CredentialId::new(id),
        folder_id: None,
        name: format!("cred-{id}"),
        kind: CredentialKind::Password,
        username: username.map(str::to_string),
    }
}

fn secret_str(auth: &cm_core::ResolvedAuth) -> Option<String> {
    auth.secret
        .as_ref()
        .map(|s| String::from_utf8(s.expose().to_vec()).unwrap())
}

// ---------------------------------------------------------------------------
// None (inherit) — no credential anywhere
// ---------------------------------------------------------------------------

#[test]
fn inherit_with_no_group_and_no_default_yields_no_secret_and_settings_username() {
    let conn = rdp_conn(1, None, None, Some("inline-user"), None);
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "inline-user");
    assert_eq!(resolved.domain, None);
    assert!(resolved.secret.is_none());
}

#[test]
fn inherit_with_empty_settings_username_yields_empty_username() {
    let conn = rdp_conn(1, None, None, None, None);
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "");
    assert!(resolved.secret.is_none());
}

// ---------------------------------------------------------------------------
// None (inherit) — group-ancestor default_credential
// ---------------------------------------------------------------------------

#[test]
fn inherit_walks_to_direct_group_default_credential() {
    let group = make_group(10, None, Some(7));
    let conn = rdp_conn(1, Some(10), None, Some("inline"), None);
    let creds = vec![make_credential(7, Some("group-admin"))];
    let store = MockCredentialStore::new().with_object(
        CredentialId::new(7),
        CredentialPurpose::Password,
        "grouppw",
    );

    let resolved =
        resolve_connection_auth(&conn, &[group], &creds, &store, CredentialPurpose::Password)
            .unwrap();
    assert_eq!(resolved.username, "group-admin");
    assert_eq!(secret_str(&resolved).as_deref(), Some("grouppw"));
}

#[test]
fn inherit_walks_to_nearest_ancestor_not_a_farther_one() {
    let grandparent = make_group(20, None, Some(1));
    let parent = make_group(21, Some(20), Some(2));
    let conn = rdp_conn(1, Some(21), None, None, None);
    let creds = vec![
        make_credential(1, Some("grandparent-admin")),
        make_credential(2, Some("parent-admin")),
    ];
    let store = MockCredentialStore::new().with_object(
        CredentialId::new(2),
        CredentialPurpose::Password,
        "parentpw",
    );

    let resolved = resolve_connection_auth(
        &conn,
        &[grandparent, parent],
        &creds,
        &store,
        CredentialPurpose::Password,
    )
    .unwrap();
    assert_eq!(resolved.username, "parent-admin", "nearest ancestor wins");
}

#[test]
fn inherit_secret_miss_is_none_not_an_error() {
    let group = make_group(10, None, Some(7));
    let conn = rdp_conn(1, Some(10), None, None, None);
    let store = MockCredentialStore::new(); // nothing stored for id 7
    let resolved =
        resolve_connection_auth(&conn, &[group], &[], &store, CredentialPurpose::Password).unwrap();
    assert!(resolved.secret.is_none());
}

#[test]
fn inherit_secret_backend_error_propagates() {
    let group = make_group(10, None, Some(7));
    let conn = rdp_conn(1, Some(10), None, None, None);
    let store = MockCredentialStore::new()
        .failing_object(CredentialId::new(7), CredentialPurpose::Password);
    let err = resolve_connection_auth(&conn, &[group], &[], &store, CredentialPurpose::Password)
        .expect_err("a genuine backend failure must propagate, not resolve to no-secret");
    assert!(matches!(err, CredentialError::Backend(_)));
}

// ---------------------------------------------------------------------------
// Object(id) — explicit, never falls back to the group chain
// ---------------------------------------------------------------------------

#[test]
fn object_source_wins_even_when_a_group_default_also_exists() {
    let group = make_group(10, None, Some(999)); // a different credential the group would default to
    let conn = rdp_conn(
        1,
        Some(10),
        Some(CredentialSource::Object(CredentialId::new(6))),
        None,
        None,
    );
    let creds = vec![
        make_credential(999, Some("group-admin")),
        make_credential(6, Some("explicit-admin")),
    ];
    let store = MockCredentialStore::new().with_object(
        CredentialId::new(6),
        CredentialPurpose::Password,
        "explicitpw",
    );

    let resolved =
        resolve_connection_auth(&conn, &[group], &creds, &store, CredentialPurpose::Password)
            .unwrap();
    assert_eq!(
        resolved.username, "explicit-admin",
        "explicit Object must not fall back to the group"
    );
    assert_eq!(secret_str(&resolved).as_deref(), Some("explicitpw"));
}

#[test]
fn object_username_wins_when_non_empty() {
    let conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Object(CredentialId::new(6))),
        None,
        None,
    );
    let creds = vec![make_credential(6, Some("admin-from-cred"))];
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &creds, &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "admin-from-cred");
}

#[test]
fn object_username_falls_back_to_settings_when_credential_username_empty() {
    let conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Object(CredentialId::new(6))),
        Some("settings-user"),
        None,
    );
    let creds = vec![make_credential(6, Some(""))];
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &creds, &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "settings-user");
}

#[test]
fn object_username_falls_back_to_settings_when_credential_missing_from_slice() {
    // Regression-shaped: the credential id is assigned but somehow absent from
    // the `credentials` slice passed in (e.g. a stale reference) — must not
    // panic, falls back to settings.
    let conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Object(CredentialId::new(6))),
        Some("settings-user"),
        None,
    );
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "settings-user");
}

#[test]
fn object_secret_present() {
    let conn = ssh_conn(
        1,
        None,
        Some(CredentialSource::Object(CredentialId::new(4))),
        "bob",
    );
    let store = MockCredentialStore::new().with_object(
        CredentialId::new(4),
        CredentialPurpose::Password,
        "s3cret",
    );
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(secret_str(&resolved).as_deref(), Some("s3cret"));
}

#[test]
fn object_secret_absent_is_a_miss_not_an_error() {
    let conn = ssh_conn(
        1,
        None,
        Some(CredentialSource::Object(CredentialId::new(4))),
        "bob",
    );
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert!(resolved.secret.is_none());
}

#[test]
fn object_ssh_key_purpose_is_independent_of_password_purpose() {
    // SSH PublicKey auth calls this twice — once per purpose. Storing only
    // the key (no passphrase) must resolve the key and leave the passphrase
    // purpose as a miss, not an error.
    let conn = ssh_conn(
        1,
        None,
        Some(CredentialSource::Object(CredentialId::new(4))),
        "bob",
    );
    let store = MockCredentialStore::new().with_object(
        CredentialId::new(4),
        CredentialPurpose::SshKey,
        "PEM-DATA",
    );

    let key = resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::SshKey).unwrap();
    assert_eq!(secret_str(&key).as_deref(), Some("PEM-DATA"));

    let passphrase =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::SshPassphrase).unwrap();
    assert!(passphrase.secret.is_none());
}

// ---------------------------------------------------------------------------
// Inline — overrides both the group chain and would-be object resolution
// ---------------------------------------------------------------------------

#[test]
fn inline_overrides_group_default_credential() {
    let group = make_group(10, None, Some(999));
    let conn = rdp_conn(
        1,
        Some(10),
        Some(CredentialSource::Inline {
            username: "inline-admin".to_string(),
            domain: None,
            has_secret: true,
        }),
        None,
        None,
    );
    let creds = vec![make_credential(999, Some("group-admin"))];
    let store = MockCredentialStore::new().with_connection(
        ConnectionId::new(1),
        CredentialPurpose::Password,
        "inlinepw",
    );

    let resolved =
        resolve_connection_auth(&conn, &[group], &creds, &store, CredentialPurpose::Password)
            .unwrap();
    assert_eq!(
        resolved.username, "inline-admin",
        "inline must win over the group default"
    );
    assert_eq!(secret_str(&resolved).as_deref(), Some("inlinepw"));
}

#[test]
fn inline_domain_is_authoritative_over_settings_domain() {
    let conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Inline {
            username: "u".to_string(),
            domain: Some("INLINE-DOMAIN".to_string()),
            has_secret: false,
        }),
        None,
        Some("SETTINGS-DOMAIN"),
    );
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.domain.as_deref(), Some("INLINE-DOMAIN"));
}

#[test]
fn inline_username_falls_back_to_settings_when_inline_username_empty() {
    let conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Inline {
            username: String::new(),
            domain: None,
            has_secret: false,
        }),
        Some("settings-user"),
        None,
    );
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "settings-user");
}

#[test]
fn inline_has_secret_true_fetches_the_connection_scoped_secret() {
    let conn = ssh_conn(
        5,
        None,
        Some(CredentialSource::Inline {
            username: "svc".to_string(),
            domain: None,
            has_secret: true,
        }),
        "unused",
    );
    let store = MockCredentialStore::new().with_connection(
        ConnectionId::new(5),
        CredentialPurpose::Password,
        "hunter2",
    );
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(secret_str(&resolved).as_deref(), Some("hunter2"));
}

#[test]
fn inline_has_secret_false_never_touches_the_store() {
    // A store that errors on ANY get() would fail this test if
    // resolve_connection_auth ever called it despite `has_secret: false`.
    struct AlwaysFailStore;
    impl cm_core::CredentialStore for AlwaysFailStore {
        fn store(&self, _key: &CredentialRef, _secret: &Secret) -> Result<(), CredentialError> {
            unimplemented!()
        }
        fn get(&self, _key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
            Err(CredentialError::Backend("must not be called".to_string()))
        }
        fn delete(&self, _key: &CredentialRef) -> Result<(), CredentialError> {
            unimplemented!()
        }
    }

    let conn = ssh_conn(
        5,
        None,
        Some(CredentialSource::Inline {
            username: "svc".to_string(),
            domain: None,
            has_secret: false,
        }),
        "unused",
    );
    let resolved = resolve_connection_auth(
        &conn,
        &[],
        &[],
        &AlwaysFailStore,
        CredentialPurpose::Password,
    )
    .expect("must not touch the store, so no error surfaces");
    assert!(resolved.secret.is_none());
}

#[test]
fn inline_never_resolves_a_secret_for_a_non_password_purpose() {
    // Inline is password-only (non-goal: no inline SSH keys) — even with
    // has_secret: true, a SshKey-purpose lookup must stay None, never
    // fall through to the connection-scoped Password entry.
    let conn = ssh_conn(
        5,
        None,
        Some(CredentialSource::Inline {
            username: "svc".to_string(),
            domain: None,
            has_secret: true,
        }),
        "unused",
    );
    let store = MockCredentialStore::new().with_connection(
        ConnectionId::new(5),
        CredentialPurpose::Password,
        "hunter2",
    );
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::SshKey).unwrap();
    assert!(resolved.secret.is_none());
}

// ---------------------------------------------------------------------------
// Prompt — explicit, never resolves a secret
// ---------------------------------------------------------------------------

#[test]
fn prompt_yields_no_secret_regardless_of_a_stored_secret() {
    // Even if a keychain entry happens to exist (e.g. left over from an
    // earlier mode), Prompt must never fetch or return it.
    let conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Prompt),
        Some("settings-user"),
        None,
    );
    let store = MockCredentialStore::new().with_connection(
        ConnectionId::new(1),
        CredentialPurpose::Password,
        "leftover-secret",
    );
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "settings-user");
    assert_eq!(resolved.domain, None);
    assert!(resolved.secret.is_none());
}

#[test]
fn prompt_on_local_connection_has_empty_username_and_no_secret() {
    let conn = local_conn(1, Some(CredentialSource::Prompt));
    let store = MockCredentialStore::new();
    let resolved =
        resolve_connection_auth(&conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(resolved.username, "");
    assert!(resolved.secret.is_none());
}

// ---------------------------------------------------------------------------
// Username precedence, end to end (the exact class of bug this suite guards)
// ---------------------------------------------------------------------------

#[test]
fn username_precedence_inline_beats_object_beats_settings() {
    let settings_username = "settings-user";

    // Object present, no inline: object's username wins over settings.
    let object_conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Object(CredentialId::new(6))),
        Some(settings_username),
        None,
    );
    let creds = vec![make_credential(6, Some("object-user"))];
    let store = MockCredentialStore::new();
    let object_resolved = resolve_connection_auth(
        &object_conn,
        &[],
        &creds,
        &store,
        CredentialPurpose::Password,
    )
    .unwrap();
    assert_eq!(object_resolved.username, "object-user");

    // Inline present: inline wins outright (doesn't even consult `creds`).
    let inline_conn = rdp_conn(
        1,
        None,
        Some(CredentialSource::Inline {
            username: "inline-user".to_string(),
            domain: None,
            has_secret: false,
        }),
        Some(settings_username),
        None,
    );
    let inline_resolved = resolve_connection_auth(
        &inline_conn,
        &[],
        &creds,
        &store,
        CredentialPurpose::Password,
    )
    .unwrap();
    assert_eq!(inline_resolved.username, "inline-user");

    // Nothing assigned at all: settings is the only source left.
    let bare_conn = rdp_conn(1, None, None, Some(settings_username), None);
    let bare_resolved =
        resolve_connection_auth(&bare_conn, &[], &[], &store, CredentialPurpose::Password).unwrap();
    assert_eq!(bare_resolved.username, settings_username);
}
