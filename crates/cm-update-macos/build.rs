//! Link the separately-built Swift bridge when this adapter is compiled for
//! macOS. The release workflow fetches Sparkle 2.9.4 and builds the bridge
//! before invoking Cargo; local Rust-only builds may leave the variables unset
//! and use this crate only for its platform-neutral event tests.

fn main() {
    println!("cargo:rerun-if-env-changed=CONMAN_SPARKLE_BRIDGE_DIR");
    println!("cargo:rerun-if-env-changed=CONMAN_SPARKLE_FRAMEWORK_DIR");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let Some(bridge_dir) = std::env::var_os("CONMAN_SPARKLE_BRIDGE_DIR") else {
        println!(
            "cargo:warning=cm-update-macos: CONMAN_SPARKLE_BRIDGE_DIR is unset; official macOS builds must build and link the Sparkle bridge"
        );
        return;
    };
    println!(
        "cargo:rustc-link-search=native={}",
        bridge_dir.to_string_lossy()
    );
    println!("cargo:rustc-link-lib=dylib=ConManSparkleBridge");
    // The packaged app embeds both dylibs below Contents/Frameworks.
    println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../Frameworks");
}
