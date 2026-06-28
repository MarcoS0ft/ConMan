//! Build script for the `conman` binary.
//!
//! Purpose: on Windows, place `ghostty-vt.dll` next to the produced
//! `conman.exe` automatically, so `cargo run`/`cargo build` "just work" with no
//! manual copy step (and no risk of the historical clobber bug where the exe
//! was overwritten by a copy).
//!
//! Background: `libghostty-vt-sys` links the engine **statically** on Linux/macOS
//! (`libghostty-vt.a`), so there is no runtime library to ship there — this
//! script is a no-op on those targets. On Windows, the `-sys` 0.2.0 crate links
//! against the DLL **import** library (`ghostty-vt.lib`), so `ghostty-vt.dll`
//! must sit beside the exe at runtime. We copy it into the profile directory
//! under its own name (never onto `conman.exe`).
//!
//! Ordering + discovery: `conman` declares `libghostty-vt-sys` as a
//! **build-dependency** purely so this script runs *after* the engine's native
//! build and receives its `links` metadata. The `-sys` crate exports its install
//! `include` directory as `cargo:include`, surfaced here as
//! `DEP_GHOSTTY_VT_INCLUDE`; the DLL sits in the sibling `bin/` directory. If
//! that variable is ever absent we fall back to scanning the cargo build tree.

use std::fs;
use std::path::{Path, PathBuf};

const DLL_NAME: &str = "ghostty-vt.dll";

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_GHOSTTY_VT_INCLUDE");

    // Only Windows links the engine as a DLL; elsewhere it is static.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let Ok(out_dir) = std::env::var("OUT_DIR").map(PathBuf::from) else {
        return;
    };

    // OUT_DIR = <target>/<profile>/build/conman-<hash>/out
    // ancestors: [0]=out [1]=conman-<hash> [2]=build [3]=<profile>
    let Some(profile_dir) = out_dir.ancestors().nth(3) else {
        return;
    };
    let build_dir = out_dir.ancestors().nth(2);

    let Some(src_dll) =
        locate_dll_via_dep_metadata().or_else(|| build_dir.and_then(scan_build_dir))
    else {
        println!(
            "cargo:warning=conman: could not locate {DLL_NAME} (DEP_GHOSTTY_VT_INCLUDE \
             unset and no -sys output found); the app will not start until it is \
             placed next to conman.exe"
        );
        return;
    };

    // Re-copy whenever the engine DLL is rebuilt.
    println!("cargo:rerun-if-changed={}", src_dll.display());

    let dest_dll = profile_dir.join(DLL_NAME);
    if needs_copy(&src_dll, &dest_dll)
        && let Err(e) = fs::copy(&src_dll, &dest_dll)
    {
        println!(
            "cargo:warning=conman: failed to copy {} -> {}: {e}",
            src_dll.display(),
            dest_dll.display()
        );
    }
}

/// Resolve the DLL from the `-sys` crate's `links` metadata: `DEP_GHOSTTY_VT_INCLUDE`
/// points at `<install>/ghostty-install/include`; the DLL is in `../bin/`.
fn locate_dll_via_dep_metadata() -> Option<PathBuf> {
    let include = std::env::var_os("DEP_GHOSTTY_VT_INCLUDE")?;
    for include_dir in std::env::split_paths(&include) {
        let dll = include_dir.parent()?.join("bin").join(DLL_NAME);
        if dll.is_file() {
            return Some(dll);
        }
    }
    None
}

/// Fallback: scan `<build_dir>/libghostty-vt-sys-*/out/ghostty-install/bin/` for the
/// DLL, preferring the most recently modified one.
fn scan_build_dir(build_dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(build_dir).ok()?.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with("libghostty-vt-sys-")
        {
            continue;
        }
        let dll = entry
            .path()
            .join("out")
            .join("ghostty-install")
            .join("bin")
            .join(DLL_NAME);
        let Ok(meta) = fs::metadata(&dll) else {
            continue;
        };
        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(t, _)| mtime >= *t) {
            best = Some((mtime, dll));
        }
    }
    best.map(|(_, path)| path)
}

/// Copy only when the destination is missing or differs (by size or mtime),
/// avoiding needless writes and never clobbering an up-to-date file.
fn needs_copy(src: &Path, dest: &Path) -> bool {
    let (Ok(src_meta), Ok(dest_meta)) = (fs::metadata(src), fs::metadata(dest)) else {
        return true; // destination missing (or src unreadable -> let copy surface it)
    };
    if src_meta.len() != dest_meta.len() {
        return true;
    }
    match (src_meta.modified(), dest_meta.modified()) {
        (Ok(s), Ok(d)) => s > d,
        _ => true,
    }
}
