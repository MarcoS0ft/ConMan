//! `cm-core` — the hexagonal core of ConMan.
//!
//! Holds the domain entities (connections, groups, profiles, credential
//! references, connection kinds), their value objects, and the **port traits**
//! that adapters implement. Pure logic only: no I/O, no protocol or storage
//! libraries. Every other crate depends inward on this one.

pub const NAME: &str = "cm-core";
