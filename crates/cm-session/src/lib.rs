//! `cm-session` — session orchestration for ConMan.
//!
//! Owns live connections (which outlive tabs) via the `SessionManager` and
//! implements the `SessionProvider` adapters for RDP, SSH, and local shell, the
//! `TerminalEngine` port and its adapters, and the PTY plumbing. Bytes cross
//! channels; protocol state stays on its owning thread.

pub const NAME: &str = "cm-session";
