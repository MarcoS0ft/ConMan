# ConMan configuration reference

ConMan stores user preferences in `conman.ini`. Connections and credentials
are deliberately not stored in this file: connections remain in SQLite and
credentials remain in the operating system's credential store.

## Location and selection

The default path uses the operating system's per-user configuration directory:

- Linux: `$XDG_CONFIG_HOME/conman/conman.ini`, normally
  `~/.config/conman/conman.ini`.
- macOS: `~/Library/Application Support/conman/conman.ini`.
- Windows: `%APPDATA%\conman\conman.ini`.

Set `CONMAN_CONFIG_PATH` or pass `--config PATH` to `conman` or `conmanctl` to
select another file. The command-line option takes precedence. ConMan does not
search for or migrate older filenames.

Useful commands:

```text
conmanctl config path
conmanctl config validate
conmanctl config validate another.ini
conmanctl config export backup.ini
conmanctl config import backup.ini
```

Export refuses to overwrite an existing output file. Import validates first and
then atomically replaces the selected configuration. Importing a file that
enables or broadens automation requires explicit acknowledgement; see
`conmanctl config import --help`.

## Syntax

The `.ini` extension makes the file easy to recognize and open in a text
editor. ConMan intentionally uses a small, flat key/value format without INI
sections:

```ini
# Lines beginning with # are comments.
theme = system
terminal-theme = dark
font-family = "JetBrainsMono Nerd Font Mono"
scrollback-limit = 10000
```

- Keys are lowercase ASCII letters, digits, and hyphens, and must begin with a
  letter.
- Whitespace surrounding the key, `=`, and value is ignored.
- Quote values when leading or trailing whitespace must be preserved. Inside a
  quoted value, only `\"` and `\\` are escape sequences.
- `#` starts a comment only when it is the first non-whitespace character on a
  line; it is literal inside a value.
- An empty value resets that setting to its built-in default.
- Duplicate keys produce a warning and the final assignment wins.
- Unknown well-formed keys are preserved, which permits manual annotations and
  forward-compatible editing, but they have no effect on ConMan.
- Invalid known values produce a warning and that individual setting uses its
  default. Syntax errors prevent the document from loading.

ConMan preserves comments, unknown keys, ordering, and line endings when it
updates known settings. Writes are atomic and serialized across ConMan
processes.

## Settings

Boolean values are exactly `true` or `false`; values are case-sensitive.

| Setting | Values and default | Effect |
|---|---|---|
| `theme` | `system` (default), `dark`, `light` | Application shell theme. |
| `accent-color` | `blue` (default), `teal`, `green`, `purple`, `system` | Application accent color. |
| `density` | `compact` (default), `cosy` | Application control spacing and density. |
| `terminal-theme` | `dark` (default), `light` | Terminal palette, independent of the application shell theme. |
| `font-family` | Font family name; default `JetBrainsMono Nerd Font Mono` | Terminal font family. |
| `font-size` | Integer `6` through `72`; default `14` | Terminal font size in points. |
| `scrollback-limit` | Integer `0` through `32768`; default `10000` | Maximum exposed history lines for new terminal sessions; `0` disables history. A separate 64 MiB backing limit per session can retain fewer content-dense rows. |
| `command` | Executable path; empty by default | Local terminal command. Empty uses the platform default shell. Applies to new local sessions. |
| `command-args` | Command-line text; empty by default | Arguments for new local terminal sessions. |
| `working-directory` | Directory path; empty by default | Working directory for new local terminal sessions. Empty uses the user's home directory. |
| `startup` | `clean` (default), `restore` | Start with a clean workspace or restore the previous session layout on the next launch. |
| `renderer-backend` | `auto` (default), `software`, `accelerated` | Renderer selection for the next launch. `auto` probes and caches a working backend. |
| `plain-copy-paste-shortcuts` | `true` (default) | Enables context-aware Ctrl+C and Ctrl+V terminal shortcuts in addition to shifted aliases. |
| `copy-on-select` | `false` (default) | Copies a completed terminal selection and clears it after a successful clipboard write. |
| `confirm-close-active-tab` | `true` (default) | Confirms before closing a tab that contains an active connection. |
| `confirm-quit-active-connections` | `true` (default) | Confirms before quitting while connections are active. |
| `auto-accept-ssh-host-keys` | `false` (default) | Automatically accepts and remembers unknown or changed SSH host keys. |
| `auto-accept-rdp-certificates` | `false` (default) | Automatically accepts and remembers RDP certificates that fail normal identity validation. |
| `automation-enabled` | `false` (default) | Enables the MCP automation endpoint when the build includes agent mode. |
| `automation-scopes` | Comma-separated subset of `read`, `write`, `execute`; empty by default | Grants MCP automation capabilities when automation is enabled. |

Most visual and interaction settings apply immediately when changed through
the UI. Settings explicitly described as affecting new sessions or the next
launch do not retroactively rebuild existing sessions.

## Security-sensitive settings

Keep both automatic trust settings disabled on untrusted networks.
`auto-accept-ssh-host-keys` accepts changed keys as well as first-seen keys, and
`auto-accept-rdp-certificates` accepts failures such as an unknown issuer,
expiry, hostname mismatch, or a changed saved certificate. They do not bypass
the underlying protocol's cryptography or authentication. Turning either
setting off does not delete identities accepted while it was enabled.

Enabling `automation-enabled` exposes the configured MCP endpoint. Grant only
the minimum required `automation-scopes`; `write` permits data changes and
`execute` permits connection actions.
