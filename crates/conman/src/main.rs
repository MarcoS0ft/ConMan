//! `conman` — the application binary and composition root.
//!
//! In later phases this is where concrete adapters are constructed and injected
//! into the UI and session layers, and where the tokio and Slint event loops
//! start. For now it only proves the workspace dependency graph wires up by
//! naming every library crate.

fn main() {
    for name in [
        cm_core::NAME,
        cm_storage::NAME,
        cm_secrets::NAME,
        cm_session::NAME,
        cm_platform::NAME,
        cm_ui::NAME,
    ] {
        println!("{name}");
    }
}
