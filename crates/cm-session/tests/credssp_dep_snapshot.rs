//! CredSSP/NLA dependency-snapshot drift guard.
//!
//! `crates/cm-session` and `vendor/{ironrdp-connector,ironrdp-async,sspi}`
//! depend on a **hand-built, pinned RustCrypto pre-release snapshot**. The
//! dependency snapshot makes russh
//! 0.61.2 (stable `rand 0.10` / RC ecdsa/rsa pins) coexist with
//! ironrdp-connector's `credssp` feature (picky/sspi, their own RC
//! ecdsa/rsa/p256/crypto-bigint pins). It works *only* because every crate
//! that both sides share resolves to a single instance in `Cargo.lock` at
//! these exact versions. Any of the following silently breaks that
//! coexistence and must fail loudly, not as a runtime "duplicate provider" /
//! resolver panic discovered much later:
//! - a `cargo update` that drifts one shared RustCrypto crate off the
//!   snapshot (e.g. a future russh bump, or a registry `sspi`/`picky` release
//!   nudging a transitive pin);
//! - editing `vendor/sspi`'s pin-bumped `Cargo.toml` back toward its stock
//!   upstream pins;
//! - bumping `vendor/ironrdp-connector`'s `picky`/`sspi` version requirements
//!   without re-validating the whole snapshot.
//!
//! This test parses the **workspace** `Cargo.lock` (not `cargo metadata` —
//! zero new dev-dependency, see CONVENTIONS §4) and asserts the exact
//! resolved version of every crate in the snapshot. A failure here means:
//! stop, re-derive the pins
//! (or, if RustCrypto 1.0 has landed everywhere, do the vendoring removal the
//! cleanup ticket describes instead of re-pinning).

use std::collections::HashMap;
use std::path::PathBuf;

/// The exact dependency snapshot
/// ("Exact dep changes" / "Crypto-graph coexistence proof"), reproduced onto
/// Keep this list synchronized with the vendored dependency pins.
const PINNED_SNAPSHOT: &[(&str, &str)] = &[
    // The two ends of the coexistence problem.
    ("russh", "0.61.2"),
    ("sspi", "0.21.0"),
    // picky 7.0.0-rc.24 is the only picky release whose RustCrypto pins match
    // russh 0.61.2 exactly; this is the load-bearing pin.
    ("picky", "7.0.0-rc.24"),
    // Shared RustCrypto crates that must unify to one instance.
    ("ecdsa", "0.17.0-rc.18"),
    ("rsa", "0.10.0-rc.18"),
    ("crypto-bigint", "0.7.5"),
    ("elliptic-curve", "0.14.0-rc.33"),
    ("p256", "0.14.0-rc.10"),
    ("curve25519-dalek", "5.0.0-rc.0"),
    // The single TLS crypto provider (credssp must not introduce a second).
    ("ring", "0.17.14"),
    ("rustls", "0.23.41"),
];

/// Finds the workspace root by walking up from this crate's manifest dir
/// until a `Cargo.lock` is found — avoids hardcoding a relative-path depth
/// that would silently stop working if the crate ever moved.
fn workspace_lock_path() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("Cargo.lock");
        if candidate.is_file() {
            return candidate;
        }
        assert!(
            dir.pop(),
            "walked up to filesystem root without finding a Cargo.lock"
        );
    }
}

/// Parses `name = "..."` / `version = "..."` pairs out of a `Cargo.lock`
/// (lockfile format v3/v4: one `[[package]]` table per crate, `name` then
/// `version` as the first two keys). Deliberately not a full TOML parser —
/// this file's shape is stable and adding a TOML dependency to a production
/// crate for one test would itself need a separate dependency.
///
/// Returns the **first** version seen for each name (irrelevant here: every
/// pinned snapshot name in this test resolves to exactly one version, which
/// is the entire point being asserted).
fn parse_lockfile_versions(contents: &str) -> HashMap<String, String> {
    let mut versions = HashMap::new();
    let mut pending_name: Option<String> = None;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("name = \"") {
            pending_name = rest.strip_suffix('"').map(str::to_owned);
        } else if let Some(rest) = line.strip_prefix("version = \"")
            && let (Some(name), Some(version)) = (pending_name.take(), rest.strip_suffix('"'))
        {
            versions.entry(name).or_insert_with(|| version.to_owned());
        }
    }
    versions
}

#[test]
fn credssp_dep_snapshot_matches_pinned_versions() {
    let lock_path = workspace_lock_path();
    let contents = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", lock_path.display()));
    let resolved = parse_lockfile_versions(&contents);

    let mut drifted = Vec::new();
    for (name, expected) in PINNED_SNAPSHOT {
        match resolved.get(*name) {
            Some(actual) if actual == expected => {}
            Some(actual) => drifted.push(format!("{name}: expected {expected}, got {actual}")),
            None => drifted.push(format!(
                "{name}: expected {expected}, but not in Cargo.lock at all"
            )),
        }
    }

    assert!(
        drifted.is_empty(),
        "CredSSP dependency snapshot drifted; inspect vendored dependency pins \
         before updating:\n{}",
        drifted.join("\n")
    );
}
