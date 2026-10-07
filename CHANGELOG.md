# Changelog

Notable changes to Connection Manager, reconstructed from Git history and
maintained here for future builds. Entries describe changes at the time they
were made; later entries can replace earlier behavior.

Dated sections identify the last mainline source checkpoint on each development
date, not published release tags. Versions use that checkpoint's Cargo base,
reachable Git commit count, and ten-character SHA. Headings before 2026-08-28
apply this scheme retrospectively, before Git-derived build versions existed.
Dates come from Git commit dates. Routine merges, formatting, and test-only
follow-ups are grouped with the behavior they support rather than repeated.

Add pending changes under `Unreleased`. For a stable release, move its pending
entries into `## [MAJOR.MINOR.PATCH] - YYYY-MM-DD`, matching the Cargo version and
`vMAJOR.MINOR.PATCH` tag. Stable GitHub releases use the matching version section below as release notes.

## [Unreleased]

## [0.2.0] - 2026-10-07

### Added

- First stable desktop release for Linux x86_64, macOS arm64, and Windows x86_64,
  including saved Local, SSH, Telnet, and RDP connections, tabs and split panes,
  reconnect, targeted input broadcast, terminal history and search, native
  credential storage, `conman.ini` preferences, and `conmanctl` administration.
- Import ConMan JSON/CSV, RoyalTS JSON, and encrypted mRemoteNG XML connections.
- RDP text/file clipboard redirection, dynamic resizing, secure attention, and
  remote cursor rendering.
- Native Linux packages, signed/notarized macOS DMG, Windows Velopack Setup/MSI
  packages, portable archives, checksums, and dedicated Sparkle signing.

### Limitations

- Automatic updates remain unavailable in the application. Browser and gateway
  foundations do not yet provide a working web client.

### Fixed

- Release workspace locks immediately when their guard drops, even while a
  duplicated or briefly inherited file handle remains open.
- Render remote RDP cursors correctly and return terminal views to the live
  cursor when typing or pasting.
- Allow SSH password logins to servers that require keyboard-interactive
  password challenges, including current FortiMail and FortiAuthenticator
  firmware, without answering OTP or password-change prompts automatically.
- Give Windows MSI packages increasing build versions for development revisions
  and patch releases, with stable builds ordered after the same development
  revision, and verify the generated installer's version.

## [0.1.0-dev.406+g50042eeaa8] - 2026-10-06

### Added

- Add update preferences, signed-manifest validation, update state handling,
  Linux staging and installation detection, Windows lifecycle hooks, and a
  macOS Sparkle bridge. Automatic updates remain unavailable in the application;
  shared update manifests and signatures are not yet published.
- Add shared application-service, browser protocol, and gateway foundations.
  The browser shell remains inert; this is not a usable web client yet.

### Changed

- Replace Windows NSIS installers with pinned Velopack Setup/MSI packages,
  full update packages, and portable ZIPs.
- Package native updater artifacts and publish macOS appcasts after packages.
- Route native workspace operations through the shared application service and
  UI controller, and consume the newest terminal/RDP surfaces during UI ticks.

### Fixed

- Display remote RDP resize, divider, text, and hand cursors, preserving
  hotspots and hidden states across tabs and split panes. Fixes #2.
- Return terminal views to the live cursor immediately when typing or pasting
  from scrollback, including when input is not echoed. Implements #1.
- Preserve full-width connection and credential IDs in UI operations.
- Retain completed workspace/editor results during service failures and UI
  refreshes, and correlate pending editor drafts with their results.
- Correct browser canvas resize sizing in the development shell.

### Security

- Bound application requests, workspace snapshots, and browser frame/control
  records; validate gateway authentication and protocol input strictly.
- Require the application service to use a host-acquired workspace guard and
  reject invalid stored credential-source combinations.
- Require the exact JSON manifest media type and avoid repeated secure
  temporary-directory scans.

## [0.1.0-dev.368+ga3009e882c] - 2026-09-08

### Changed

- Keep the terminal scrollbar visible by default with subtle resting contrast,
  emphasize it on hover or press, and offer activity-triggered fading as an option.

### Fixed

- Make scrollbar tracks clickable across their full width, page by one viewport
  without losing position, keep dragging stable, and synchronize thumb updates.
- Isolate concurrent Zig caches and dependency build graphs, and use a compatible
  macOS SDK for native builds.

## [0.1.0-dev.363+g3622ba33bb] - 2026-09-05

### Fixed

- Wire terminal scrollbar scrubbing to real scrollback offsets and synchronize
  viewport state when switching terminal tabs and panes.

## [0.1.0-dev.362+g03006f1b37] - 2026-08-31

### Changed

- Simplify Home by removing redundant Quick Connect controls, limiting recent
  connections to ten, and allowing vertical scrolling in compact windows.
- Publish project guidance and security reporting instructions.

### Security

- Keep builder home, checkout, and Zig paths out of release executables.

## [0.1.0-dev.352+gc8ca282456] - 2026-08-30

### Added

- Add mouse tab reordering, Ctrl+Tab switching, Ctrl+0 for Home, and Ctrl+1
  through Ctrl+9 for direct access to connection tabs.
- Add native Linux DEB, RPM, AppImage, portable, and static-musl packages;
  macOS DMGs with a bundled `conmanctl` installer; and Windows NSIS installers
  and portable ZIPs. Windows packaging is replaced by Velopack on 2026-10-06.
- Add Developer ID signing, notarization, stapling, and Gatekeeper validation
  for macOS rolling builds, and include licenses, font notices, and checksums
  with native packages.
- Add independent lab-mode settings to automatically trust and remember SSH
  host keys and RDP certificates.

### Changed

- Remove the unused activity-bar placeholder and the hard-coded Launchpad
  split-connection action.
- Store Linux credentials persistently in the freedesktop Secret Service,
  requiring a running, unlocked provider rather than a session-only keyring.
- Use the macOS data-protection Keychain, shared by the signed GUI and bundled
  CLI through an explicitly authorized Keychain Access Group.

### Fixed

- Unify keyboard and mouse tab activation, preserve focus on repeated shortcuts,
  keep Home pinned, and show tab drag source/destination previews.
- Ship required redistribution notices and accept verified static-musl PIE output.

### Security

- Keep identity auto-accept disabled by default, warn and audit when enabled,
  and fail when an accepted identity cannot be remembered.
- Require separate GUI and CLI provisioning profiles authorizing their shared
  Keychain Access Group before producing signed macOS packages.

## [0.1.0-dev.338+gdfd4565397] - 2026-08-28

### Added

- Add editable `conman.ini` preferences, keeping saved connections in SQLite,
  secrets in native credential stores, and machine-local state separate.
- Add `conmanctl` connection/configuration import, export, inspection, validation,
  and shell completion, plus GUI `--config` and `--database` overrides.
- Add application branding, platform-aware local-shell hints, build identity
  display, and Git-derived development versions based on the new `0.1.0` base.
- Add configurable terminal history, plain Ctrl+C/Ctrl+V aliases, tracking-aware
  pointer paste, copy-on-selection, close confirmations, and protocol-specific
  session actions.
- Add versioned cross-platform release archives. Linux and Windows release
  executables use checksum-verified UPX compression; macOS does not use UPX.

### Changed

- Keep terminal colors independent of the application light/dark theme.
- Scope single-instance activation to the selected configuration and database.
- Make connection imports transactional and secret-inclusive exports fail when
  a requested secret cannot be retrieved.
- Bound terminal history to a configurable 10,000-line default with an
  independent 64 MiB backing limit per session.

### Fixed

- Show native error dialogs with sanitized technical details and relevant paths
  when application startup fails.
- Ignore standalone modifier presses without breaking terminal clipboard aliases.
- Preserve physical RDP modifier chords and translate Ctrl+Alt+End at the client;
  Session Actions now sends the actual Ctrl+Alt+Delete sequence.
- Keep session-action menus compact and anchored to their tab-strip trigger.
- Restore command-palette keyboard ownership, Escape handling, and empty search
  state on reopen, without leaking keys to terminal sessions.
- Report consistent physical CSV source-line numbers for LF and CRLF input.

### Security

- Harden configuration and instance coordination against symlink, reparse-point,
  replacement, and concurrent-writer attacks.
- Replace changed SSH trust entries atomically while leaving the user's OpenSSH
  `known_hosts` file read-only.

## [0.0.0-dev.311+g57075f2e79] - 2026-08-27

### Added

- Add reliable bidirectional RDP text and file clipboard redirection, including
  Windows virtual files for nested RDP sessions.
- Add Linux, macOS, and Windows build/test CI jobs.

### Fixed

- Keep dense shell, settings, palette, and dialog layouts reachable, and settle
  split-pane geometry after layout changes.
- Preserve saved profile titles across launches, reconnects, and pane promotion.
- Make Ctrl+K global and forward RDP modifiers without spurious characters.

### Security

- Stage redirected clipboard files securely, bound protocol work, clean up
  transfer leases, and avoid logging clipboard payloads.

## [0.0.0-dev.308+g90b79e1a2e] - 2026-08-26

### Added

- Shape complete terminal graphemes using bundled and installed font fallback,
  and add live system-font selection.
- Import RoyalTS Telnet profiles and confirm recursive connection-group deletion.

### Fixed

- Restore terminal mouse selection and improve font/settings scrolling behavior.

## [0.0.0-dev.306+ge55c422ff1] - 2026-08-25

### Added

- Add Telnet profiles, imports, protocol negotiation, interactive sessions,
  connection editing, and terminal UI integration.

### Fixed

- Keep xrdp sessions connected during RDP resize.
- Dismiss terminal selection on a plain click.
- Preserve promoted split-pane session state.
- Validate Telnet import invariants, bound transport queues, retain progress
  under saturation, and keep buffer search nonblocking.

## [0.0.0-dev.293+gb5b63aa2aa] - 2026-07-10

### Changed

- Build the x86_64 terminal library for the explicit x86_64-v3 CPU baseline,
  rather than the builder's native CPU.
- Disable ANSI console colors when stderr lacks ANSI/VT support.

### Fixed

- Restore connection and credential row context menus.
- Treat clean SSH exit/disconnect as a normal closed session.
- Clear stale remote frames when opening another session.

## [0.0.0-dev.285+g271428707b] - 2026-07-09

### Added

- Add reusable-reference and connection-inline credential modes, with native
  credential-store lookup and cleanup when switching away from inline secrets.
- Wire CSV and mRemoteNG XML import into the file picker, including password
  prompts for encrypted mRemoteNG input and inline per-connection passwords.
- Add optional agent-mode settings, active-state indication, and execution-scope
  enforcement; agent mode remains off by default.
- Add mid-session RDP resizing through DisplayControl, including bounded
  reactivation, timeout diagnostics, and an escape hatch for unsupported servers.
- Add tab context menus, per-pane disconnect, a Home tab pill, and live connection
  status indicators in the saved-connection tree.
- Extend credential, startup, import, and connection timing diagnostics without
  exposing credential values.

### Fixed

- Keep connection/credential hover controls clickable and stable, and prevent
  reconnect, tab-switch, and connecting/error content from bleeding across tabs.
- Keep dialogs opaque and clear inline passwords on cancel or dismissal.
- Copy inline secrets when duplicating connections and count connection secrets
  in import summaries.
- Register the RDP DisplayControl channel so negotiated resize requests are sent.

### Security

- Enforce automation batch/path boundaries and execution scope for launch,
  broadcast, reconnect, and connect-in-split operations.

## [0.0.0-dev.218+g0f7e0a2d85] - 2026-07-08

### Added

- Add accessible roles, labels, stable element identifiers, and in-process UI tests.
- Add optional MCP automation, disabled by default.
- Cache renderer-backend decisions and expose renderer selection in Settings.
- Add RoyalTS JSON, ConMan CSV, and encrypted mRemoteNG XML import support in
  storage; CSV/XML file-picker wiring follows on 2026-07-09.
- Add RDP CredSSP/NLA authentication for NLA-required servers.
- Add file-backed debug logging and credential-backend, database, import/export,
  local-shell, SSH, and RDP timing diagnostics.

### Fixed

- Negotiate RSA SHA-256/SHA-512 signatures for SSH RSA public-key authentication.
- Authenticate credentialed connections with the stored credential's username.
- Keep Home correctly titled and stop seeding demo connections in ordinary builds.
- Render RDP frames opaque to avoid black screens and size connections to their
  actual pane, including connect-in-split.
- Stabilize connection-row hover actions; single click selects and double click
  launches the selected connection.

### Security

- Keep password cleartext out of accessibility values and remove internal
  CredSSP protocol traces from user-facing authentication errors.
- Remove real environment secrets and addresses from tracked QA fixtures.

## [0.0.0-dev.155+g2b2fa219de] - 2026-07-07

### Changed

- Use a two-column application shell with full-height navigation and a separate
  tab, session, and status area.
- Improve profile/group editors with opaque cards, bounded scrolling, reachable
  RDP fields, and quieter light-theme chrome.

### Fixed

- Cancel connecting sessions explicitly and abort them when their tab closes.
- Explain unsupported legacy-only RDP security and wrap long error messages.
- Synchronize native-widget color schemes with the application theme.

## [0.0.0-dev.136+g0a01bb1c7b] - 2026-07-04

### Added

- Probe accelerated rendering at startup and automatically fall back to software
  rendering when the graphics backend is unusable.

## [0.0.0-dev.133+g802ba43bcd] - 2026-07-03

### Added

- Add terminal scrollback scrolling and whole-buffer search.
- Support multiple split panes, RDP inside panes, and targeted input broadcast.
- Add RDP reconnect and protocol selection in Quick Connect.

### Changed

- Route session creation through a shared provider interface.

## [0.0.0-dev.122+gae13b3a509] - 2026-07-02

### Added

- Add structured logging and native file dialogs for connection import/export.
- Add a resizable, collapsible sidebar with persisted width and direct keyboard
  shortcuts for tab navigation and sidebar toggling.
- Add terminal selection, shared clipboard copy/paste, and bracketed paste when
  requested by the running terminal application.
- Resolve stored passwords and SSH keys at connect time, and support SSH
  keyboard-interactive prompts and the Windows SSH agent.
- Add recent connections, a Home launchpad, and optional session restoration.
- Follow the application theme in terminals and expose the OS accent color in
  Settings; independent terminal colors follow on 2026-08-28.
- Add connection/credential context menus and connect-in-split for local/SSH profiles.

### Fixed

- Show actual session status and honest connecting/error overlays.
- Restrict session overlays to their pane and avoid unnecessary selection redraws.

### Security

- Restrict environment-driven identity auto-accept hooks to debug builds.
- Bound single-instance coordination reads and write timeouts.

## [0.0.0-dev.80+ga9848fc1fb] - 2026-07-01

### Added

- Add a single-instance guard and activate the existing application on a
  second launch.
- Add an optional in-app QA endpoint and scripted UI scenarios.

### Changed

- Split UI controller responsibilities into modules and strengthen SSH/RDP
  loopback and certificate-trust regression coverage.

## [0.0.0-dev.66+g652e0a5af8] - 2026-06-28

### Added

- Store connections and credential metadata in SQLite and secrets in native
  credential stores; persist the application database between runs.
- Add connection/credential trees, editors, filtering, keyboard navigation,
  toasts, tooltips, and a searchable command palette.
- Add JSON connection import/export, SSH Quick Connect and host-key prompts,
  and saved-connection launches.
- Add RDP sessions, certificate trust prompts, desktop display, and text clipboard
  redirection; more reliable file/text redirection follows on 2026-08-27.
- Add split panes, input broadcast, detached sessions, and reattachment.
- Add persistent application settings, density controls, theme tokens, and
  cross-platform icon fonts.

### Fixed

- Keep RDP pointer scrolling tied to desktop coordinates and report connection
  failures instead of presenting failed launches as live sessions.
- Restore palette focus, split-session reattachment, broadcast/focus shortcuts,
  background pane-count badges, and first-run initialization guards.

### Security

- Write remembered RDP certificates atomically.

## [0.0.0-dev.16+gb3e08efe3f] - 2026-06-27

### Added

- Create the Rust workspace, connection/credential models, terminal engine,
  native application shell, and local PTY terminal tabs.
- Add SSH session transport and bundled Nerd Font terminal rendering.

### Fixed

- Keep terminal glyphs at fixed cell sizes during resize, avoid stale stretched
  frames, reuse shared font data, and reuse available terminal tab numbers.
- Debounce terminal resize and respond to ConPTY terminal queries to avoid
  delayed Windows shell startup.
- Hide the extra Windows console for release GUI builds.

### Changed

- Automate Zig/terminal-library setup and copy the Windows terminal DLL beside
  the executable during builds.

[Unreleased]: https://github.com/MarcoS0ft/ConMan/compare/50042eeaa8...HEAD
[0.1.0-dev.406+g50042eeaa8]: https://github.com/MarcoS0ft/ConMan/commit/50042eeaa8850447c960cad0bde1a7afe9256385
[0.1.0-dev.368+ga3009e882c]: https://github.com/MarcoS0ft/ConMan/commit/a3009e882ca179e652de2923f336fede634d9bff
[0.1.0-dev.363+g3622ba33bb]: https://github.com/MarcoS0ft/ConMan/commit/3622ba33bb5b01884e42165e590aef88cdf74caa
[0.1.0-dev.362+g03006f1b37]: https://github.com/MarcoS0ft/ConMan/commit/03006f1b375fdeafc7958c27b7b601ac1138d8af
[0.1.0-dev.352+gc8ca282456]: https://github.com/MarcoS0ft/ConMan/commit/c8ca282456a8302c571de553321ce8b105719f3e
[0.1.0-dev.338+gdfd4565397]: https://github.com/MarcoS0ft/ConMan/commit/dfd4565397fb62213792668d7d6128e2d5d7f522
[0.0.0-dev.311+g57075f2e79]: https://github.com/MarcoS0ft/ConMan/commit/57075f2e79362a1958b8dfec661f97f49cf25bd8
[0.0.0-dev.308+g90b79e1a2e]: https://github.com/MarcoS0ft/ConMan/commit/90b79e1a2e6e7a3033a1ae764f15afb7d0667878
[0.0.0-dev.306+ge55c422ff1]: https://github.com/MarcoS0ft/ConMan/commit/e55c422ff1eeda0d21d36feeeb5efb7184e6a2d4
[0.0.0-dev.293+gb5b63aa2aa]: https://github.com/MarcoS0ft/ConMan/commit/b5b63aa2aa17e5817bcb55d0fa93599efbda1dab
[0.0.0-dev.285+g271428707b]: https://github.com/MarcoS0ft/ConMan/commit/271428707bfe5363081dad3a17fab613399ae9fb
[0.0.0-dev.218+g0f7e0a2d85]: https://github.com/MarcoS0ft/ConMan/commit/0f7e0a2d850d9d18ca57deb1274a4dbe9a15824f
[0.0.0-dev.155+g2b2fa219de]: https://github.com/MarcoS0ft/ConMan/commit/2b2fa219dede47db3bbe85e0c3bc5baaeecde51a
[0.0.0-dev.136+g0a01bb1c7b]: https://github.com/MarcoS0ft/ConMan/commit/0a01bb1c7b13b28fb096980d2313d33178005e4e
[0.0.0-dev.133+g802ba43bcd]: https://github.com/MarcoS0ft/ConMan/commit/802ba43bcde129202e0a953d53fad46675dc1f6a
[0.0.0-dev.122+gae13b3a509]: https://github.com/MarcoS0ft/ConMan/commit/ae13b3a509fe47c23d92625ed62e0111b83f8b12
[0.0.0-dev.80+ga9848fc1fb]: https://github.com/MarcoS0ft/ConMan/commit/a9848fc1fbb82765779a9469eb781d5299e38045
[0.0.0-dev.66+g652e0a5af8]: https://github.com/MarcoS0ft/ConMan/commit/652e0a5af8e409376379285477841d24abd0f7c0
[0.0.0-dev.16+gb3e08efe3f]: https://github.com/MarcoS0ft/ConMan/commit/b3e08efe3f6d3b6360da8a2df0d39a5087f04e29
