//! Release-pipeline manifest generator.
//!
//! This intentionally has a small dependency-free argument parser so release
//! jobs can run it on the packaging host. Every `--artifact` is
//! `platform,architecture,kind,asset-name,path` and is read only after all
//! identity arguments have been validated.

use std::path::PathBuf;

use cm_core::UpdateChannel;
use cm_update::{
    Architecture, AssetKind, Platform, ReleaseArtifact, ReleaseIdentity, generate_manifest,
    sign_manifest,
};
use semver::Version;

fn usage() -> &'static str {
    "usage: update-manifest --channel stable|dev --tag TAG --version VERSION --revision N \
     --commit 40-hex --published-at RFC3339 --minimum-updater-version VERSION \
     --key-id ID --key-file PATH --manifest PATH --signature PATH \
     --artifact platform,architecture,kind,asset-name,path [...]"
}

fn required(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn main() -> Result<(), String> {
    let mut channel = None;
    let mut tag = None;
    let mut version = None;
    let mut revision = None;
    let mut commit = None;
    let mut published_at = None;
    let mut minimum_updater_version = None;
    let mut key_id = None;
    let mut key_file = None;
    let mut manifest_path = None;
    let mut signature_path = None;
    let mut artifacts = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || required(&mut args, &flag);
        match flag.as_str() {
            "--channel" => channel = Some(value()?),
            "--tag" => tag = Some(value()?),
            "--version" => version = Some(value()?),
            "--revision" => revision = Some(value()?),
            "--commit" => commit = Some(value()?),
            "--published-at" => published_at = Some(value()?),
            "--minimum-updater-version" => minimum_updater_version = Some(value()?),
            "--key-id" => key_id = Some(value()?),
            "--key-file" => key_file = Some(PathBuf::from(value()?)),
            "--manifest" => manifest_path = Some(PathBuf::from(value()?)),
            "--signature" => signature_path = Some(PathBuf::from(value()?)),
            "--artifact" => artifacts.push(value()?),
            "--help" | "-h" => return Err(usage().to_owned()),
            _ => return Err(format!("unknown argument `{flag}`\n{}", usage())),
        }
    }
    let channel = match channel.as_deref() {
        Some("stable") => UpdateChannel::Stable,
        Some("dev") => UpdateChannel::Dev,
        _ => return Err("--channel must be stable or dev".to_owned()),
    };
    let parse = |name: &str, value: Option<String>| {
        value.ok_or_else(|| format!("missing --{name}\n{}", usage()))
    };
    let version = Version::parse(&parse("version", version)?).map_err(|_| "invalid --version")?;
    let minimum_updater_version =
        Version::parse(&parse("minimum-updater-version", minimum_updater_version)?)
            .map_err(|_| "invalid --minimum-updater-version")?;
    let revision = parse("revision", revision)?
        .parse::<u64>()
        .map_err(|_| "invalid --revision")?;
    let commit_text = parse("commit", commit)?;
    let commit =
        decode_hex_20(&commit_text).ok_or("--commit must be 40 lowercase hex characters")?;
    let identity = ReleaseIdentity {
        channel,
        release_tag: parse("tag", tag)?,
        version,
        revision,
        commit,
        published_at: parse("published-at", published_at)?,
        minimum_updater_version,
    };
    let mut parsed_artifacts = Vec::new();
    for encoded in artifacts {
        let fields = encoded.splitn(5, ',').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err("--artifact must be platform,architecture,kind,asset-name,path".to_owned());
        }
        let platform = fields[0]
            .parse::<Platform>()
            .map_err(|_| "invalid artifact platform")?;
        let architecture = fields[1]
            .parse::<Architecture>()
            .map_err(|_| "invalid artifact architecture")?;
        let kind = fields[2]
            .parse::<AssetKind>()
            .map_err(|_| "invalid artifact kind")?;
        let bytes = std::fs::read(fields[4]).map_err(|_| "could not read artifact")?;
        parsed_artifacts.push(ReleaseArtifact {
            platform,
            architecture,
            kind,
            asset_name: fields[3].to_owned(),
            bytes,
        });
    }
    let manifest =
        generate_manifest(&identity, &parsed_artifacts).map_err(|error| error.to_string())?;
    let key_id = parse("key-id", key_id)?;
    if key_id != cm_update::DEFAULT_MANIFEST_KEY_ID {
        return Err("unexpected manifest signing key id".to_owned());
    }
    let key_file = key_file.ok_or_else(|| format!("missing --key-file\n{}", usage()))?;
    let secret = decode_key(&std::fs::read(key_file).map_err(|_| "could not read key file")?)
        .ok_or("key file must contain 32 raw bytes, 64 hex characters, or base64")?;
    let signature = sign_manifest(&manifest, key_id, secret);
    let manifest_path = manifest_path.ok_or_else(|| format!("missing --manifest\n{}", usage()))?;
    let signature_path =
        signature_path.ok_or_else(|| format!("missing --signature\n{}", usage()))?;
    std::fs::write(manifest_path, &manifest).map_err(|_| "could not write manifest")?;
    std::fs::write(signature_path, signature).map_err(|_| "could not write signature")?;
    Ok(())
}

fn decode_hex_20(value: &str) -> Option<[u8; 20]> {
    if value.len() != 40
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0; 20];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = hex(pair[0])? << 4 | hex(pair[1])?;
    }
    Some(output)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_key(value: &[u8]) -> Option<[u8; 32]> {
    if value.len() == 32 {
        return value.try_into().ok();
    }
    let text = std::str::from_utf8(value).ok()?.trim();
    if text.len() == 64 {
        let mut key = [0; 32];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            key[index] = hex(pair[0])? << 4 | hex(pair[1])?;
        }
        return Some(key);
    }
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text).ok()?;
    decoded.try_into().ok()
}
