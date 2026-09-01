fn main() {
    // When the `ui-introspection` feature is on, compile the UI with
    // Slint compiler debug info so `i-slint-backend-testing`'s ElementHandle
    // queries (element ids/roles/labels) resolve at all — without it,
    // `search_api.rs`'s `warn_missing_debug_info` fires and every query comes
    // back empty. Default builds stay debug-info-free (no element-name
    // strings baked into a release binary.
    println!("cargo:rerun-if-env-changed=SLINT_EMIT_DEBUG_INFO");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UI_INTROSPECTION");

    let want_debug_info = std::env::var_os("CARGO_FEATURE_UI_INTROSPECTION").is_some()
        || std::env::var_os("SLINT_EMIT_DEBUG_INFO").is_some();

    let config = slint_build::CompilerConfiguration::new().with_debug_info(want_debug_info);
    slint_build::compile_with_config("ui/app.slint", config).expect("slint compile failed");
}
