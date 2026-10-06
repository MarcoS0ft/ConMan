use std::{
    fs::OpenOptions,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use conman_gateway::{
    auth::{MAX_PASSWORD_BYTES, PasswordVerifier},
    config::GatewayConfig,
};
use zeroize::{Zeroize, Zeroizing};

fn main() {
    if let Err(error) = run() {
        eprintln!("conman-gateway: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let command = args.next().ok_or_else(usage)?;
    let path = args.next().map(PathBuf::from).ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    match command.to_str() {
        Some("validate-config") => {
            let config =
                GatewayConfig::load(&path).map_err(|_| "configuration rejected".to_owned())?;
            PasswordVerifier::load(&config.owner_verifier_file)
                .map_err(|_| "owner verifier rejected".to_owned())?;
            println!("configuration valid");
            Ok(())
        }
        Some("provision-owner") => provision_owner(&path),
        _ => Err(usage()),
    }
}

fn provision_owner(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("verifier path must be absolute".to_owned());
    }
    let parent = path
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| "verifier parent directory must exist".to_owned())?;
    if io::stdin().is_terminal() {
        return Err("pipe a password on stdin; interactive echo is refused".to_owned());
    }

    let mut input = Vec::new();
    io::stdin()
        .take((MAX_PASSWORD_BYTES + 3) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "could not read password from stdin".to_owned())?;
    if input.len() > MAX_PASSWORD_BYTES + 2 {
        input.zeroize();
        return Err("password exceeds 256 UTF-8 bytes".to_owned());
    }
    if input.last() == Some(&b'\n') {
        input.pop();
        if input.last() == Some(&b'\r') {
            input.pop();
        }
    }
    if input.is_empty() || input.contains(&b'\n') || input.contains(&b'\r') {
        input.zeroize();
        return Err("password input must be one non-empty line".to_owned());
    }
    let password = String::from_utf8(input).map_err(|error| {
        let mut bytes = error.into_bytes();
        bytes.zeroize();
        "password must be UTF-8".to_owned()
    })?;
    let mut password = Zeroizing::new(password);
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("password exceeds 256 UTF-8 bytes".to_owned());
    }
    let params = Params::new(65_536, 3, 4, Some(32))
        .map_err(|_| "invalid password verifier parameters".to_owned())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).map_err(|_| "could not create owner verifier".to_owned())?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|_| "could not create owner verifier".to_owned())?;
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "could not create owner verifier".to_owned())?;
    password.zeroize();
    let phc = hash.to_string();
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| "verifier parent directory unavailable".to_owned())?;
    let filename = path
        .file_name()
        .ok_or_else(|| "verifier path has no filename".to_owned())?;
    let destination = canonical_parent.join(filename);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&destination)
        .map_err(|_| "could not create owner verifier".to_owned())?;
    file.write_all(phc.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            let _ = std::fs::remove_file(&destination);
            "could not write owner verifier".to_owned()
        })?;
    println!("owner verifier created");
    Ok(())
}

fn usage() -> String {
    "usage: conman-gateway <validate-config <path> | provision-owner <absolute-path>>".to_owned()
}
