# Connection Manager

ConMan is a cross-platform desktop connection manager for local terminals,
SSH, Telnet, and RDP sessions. It combines saved connections, split panes,
tabs, terminal history, clipboard integration, and protocol-specific session
actions in one native application.

The companion `conmanctl` program provides a scriptable interface for listing,
importing, and exporting connections and configuration. Saved connections live
in SQLite, credentials use the operating system's credential store, and user
preferences remain in an editable `conman.ini` file.

## Project status

ConMan is under active development. Rolling `dev` builds are intended for
testing and may change without compatibility guarantees. Stable releases will
use semantic `vMAJOR.MINOR.PATCH` tags.

## Downloads

Rolling builds are published on the [Releases](../../releases) page for:

- Linux x86_64: DEB, RPM, AppImage, portable archive, and static-musl archive.
- macOS arm64: Developer ID-signed and notarized DMG, including `conmanctl`.
- Windows x86_64: NSIS installer and portable ZIP.

Each release includes SHA-256 checksums. Linux and Windows release executables
are UPX-compressed and verified during packaging; macOS executables are signed
and notarized without UPX.

## Getting started

Install a package for your platform, open **Connection Manager**, and use the
Home screen or **Quick Connect** to start a session. Saved connections can
reference reusable credentials from the platform credential store.

Useful command-line entry points include:

```text
conman --help
conmanctl --help
conmanctl connections list
conmanctl connections export connections.json
conmanctl connections import connections.json
```

Run `conmanctl <command> --help` for command-specific options. Imports are
currently additive; review an import before repeating it if duplicate records
would be undesirable.

## Configuration

ConMan's user preferences are stored in `conman.ini`. See the
[configuration reference](docs/configuration.md) for its location, syntax,
every supported setting, and the security implications of trust and automation
options.

The companion command can print, validate, import, and export the selected
configuration:

```text
conmanctl config path
conmanctl config validate
conmanctl config export backup.ini
conmanctl config import backup.ini
```

Configuration import replaces the selected configuration document atomically.
Connection import is a separate, additive operation.

## Credentials

- macOS uses the data-protection Keychain. Signed release builds authorize the
  GUI and bundled `conmanctl` helper through one shared Keychain Access Group.
- Windows uses Windows Credential Manager.
- Linux uses the freedesktop Secret Service. A compatible provider such as
  GNOME Keyring or KWallet must be running and unlocked.

ConMan does not store credential values in `conman.ini` or its SQLite database.
See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Building from source

The repository pins Rust 1.96.0 and requires Zig 0.15.2 for the terminal
backend. After installing the native graphics/font dependencies for your
platform:

```sh
scripts/bootstrap-zig.sh --export
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

On Windows, run `scripts/bootstrap-zig.ps1` instead. CI is the authoritative
cross-platform build and test contract. Packaging entry points and artifact
contents are documented in [packaging/README.md](packaging/README.md).

## License

ConMan is available under either the [Apache License 2.0](LICENSE-APACHE) or
the [MIT License](LICENSE-MIT), at your option. Bundled fonts retain their own
license and notice files.
