#![forbid(unsafe_code)]

pub mod auth;
pub mod config;

// Reviewed private codec foundation; the WSS consumer is a later integration.
#[allow(dead_code)]
mod streaming;
