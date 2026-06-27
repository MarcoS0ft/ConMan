//! `cm-platform` — OS plumbing for ConMan.
//!
//! Confines operating-system-specific behavior to one place: data and config
//! directory resolution, the single-instance guard, clipboard access, and DPI
//! helpers. Keeps the core and UI platform-agnostic.

pub const NAME: &str = "cm-platform";
