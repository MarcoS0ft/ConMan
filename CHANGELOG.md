# Changelog

All notable user-facing changes to Connection Manager are documented here.

## [Unreleased]

### Added

- Add an editable `config.conman` preferences file while retaining connections,
  credentials, and machine-local application state in their appropriate stores.
- Add `conmanctl` for connection and configuration import, export, inspection,
  validation, and shell completion, plus GUI `--config` and `--database`
  overrides.
- Add configurable terminal scrollback, plain Ctrl+C/Ctrl+V aliases,
  tracking-aware pointer paste, copy-on-selection, close confirmations, and
  contextual terminal and RDP session actions.
- Add application branding, platform-aware local-shell hints, build identity
  display, and commit-derived development versions.
- Add versioned Linux, macOS, and Windows release packaging with verified UPX
  compression for Linux and Windows executables.

### Changed

- Keep terminal colors independent from the application light/dark theme so a
  shell remains readable in either application theme.
- Scope single-instance activation to the selected configuration and database,
  allowing intentional independent instances without risking duplicate owners.
- Make connection imports transactional and secret-inclusive exports fail when
  any requested secret cannot be retrieved.
- Use a bounded, user-configurable terminal history with a 10,000-line default
  and an independent 64 MiB backing limit per terminal session.

### Security

- Use native platform credential stores consistently from both the GUI and
  command-line tools.
- Harden configuration and instance coordination files against symlink,
  reparse-point, replacement, and concurrent-writer attacks.
