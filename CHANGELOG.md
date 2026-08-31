# Changelog

All notable user-facing changes to Connection Manager are documented here.

## [Unreleased]

### Added

- Add an editable `conman.ini` preferences file while retaining connections,
  credentials, and machine-local application state in their appropriate stores.
- Add `conmanctl` for connection and configuration import, export, inspection,
  validation, and shell completion, plus GUI `--config` and `--database`
  overrides.
- Add configurable terminal scrollback, plain Ctrl+C/Ctrl+V aliases,
  tracking-aware pointer paste, copy-on-selection, close confirmations, and
  contextual terminal and RDP session actions.
- Add application branding, platform-aware local-shell hints, build identity
  display, and commit-derived development versions.
- Add native Linux DEB, RPM, AppImage, portable, and static distributions;
  Developer ID-signed and notarized macOS rolling/stable DMGs with a
  `conmanctl` installer; and Windows per-user or all-users NSIS and portable ZIP
  packages. Linux and Windows executables use verified UPX compression, and
  every format carries project/font notices.
- Add mouse tab reordering, Ctrl+Tab switching, Ctrl+0 for Home, and Ctrl+1
  through Ctrl+9 for direct access to connection tabs.
- Add secure-default, independently configurable lab-mode options to
  automatically trust and remember SSH host keys and RDP certificates.

### Changed

- Store macOS credentials in the modern data-protection Keychain. Developer ID
  builds give the GUI and bundled `conmanctl` helper one explicitly shared,
  team-authorized Keychain Access Group, avoiding legacy per-item ACL prompts.
- Store Linux credentials persistently in the freedesktop Secret Service,
  shared by ConMan and `conmanctl`, instead of the session-scoped kernel
  keyring. A running, unlocked Secret Service provider is required.
- Keep terminal colors independent from the application light/dark theme so a
  shell remains readable in either application theme.
- Scope single-instance activation to the selected configuration and database,
  allowing intentional independent instances without risking duplicate owners.
- Make connection imports transactional and secret-inclusive exports fail when
  any requested secret cannot be retrieved.
- Use a bounded, user-configurable terminal history with a 10,000-line default
  and an independent 64 MiB backing limit per terminal session.

### Fixed

- Unify tab keyboard and mouse activation so repeated shortcuts retain focus,
  palette dismissal can reopen immediately, Home remains pinned, and tab
  dragging clearly previews its source and destination.
- Restore command-palette keyboard ownership so Ctrl+K focuses its search,
  Escape dismisses it without leaking input to a session, and every reopen
  starts with an empty query and reset selection.
- Report consistent physical source-line numbers for CSV import warnings with
  either LF or Windows CRLF input.
- Send the actual Ctrl+Alt+Delete sequence from RDP Session Actions instead of
  forwarding the client-side Ctrl+Alt+End shortcut as remote input.
- Keep RDP keyboard chords stable by forwarding physical modifier transitions
  once and translating Ctrl+Alt+End at the client boundary.
- Show sanitized native error dialogs with technical details and relevant file
  paths when the graphical application cannot finish starting.
- Prevent standalone left/right modifier presses in terminal sessions from
  emitting control characters or triggering clipboard shortcuts.
- Keep contextual session-action menus compact and anchored to their tab-strip
  trigger instead of stretching them to the full window height.

### Security

- Use native platform credential stores consistently from both the GUI and
  command-line tools. macOS release packaging fails closed unless separate GUI
  and CLI provisioning profiles authorize their shared Keychain Access Group.
- Harden configuration and instance coordination files against symlink,
  reparse-point, replacement, and concurrent-writer attacks.
- Keep SSH and RDP identity auto-accept disabled by default, clearly warn when
  enabled, audit automatic decisions, and fail rather than claim an accepted
  identity was remembered when its trust store cannot be persisted.
- Replace changed entries in ConMan's SSH trust store atomically while keeping
  the user's OpenSSH `known_hosts` file strictly read-only.
