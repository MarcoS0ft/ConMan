// B1: run as a Windows GUI app in release (no allocated console window behind the GUI).
// Debug keeps the console so `eprintln!` diagnostics remain visible during development.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `conman` — the application binary and composition root.
//!
//! Selects the concrete Slint backend (via the `slint` feature set in `Cargo.toml`) and
//! launches the UI. As later phases add storage/secrets/network adapters, this is where
//! they are constructed and injected; for P2.4 the app is a local-terminal workbench whose
//! Slint wiring lives in `cm_ui::run`.
//!
//! The `slint` dependency is declared to enable the windowing backend + renderers for the
//! shared build (Cargo feature unification); the event loop itself is entered by
//! `cm_ui::run`.

use std::process::ExitCode;

// Pull the backend/renderer features into the shared `slint` build. Not otherwise used
// here — the event loop is owned by `cm_ui`.
use slint as _;

fn main() -> ExitCode {
    match cm_ui::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("conman: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
