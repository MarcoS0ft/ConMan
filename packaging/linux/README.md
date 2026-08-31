# ConMan Linux packages

Linux has four distribution formats. All package builders consume an already
built `conman` and `conmanctl`; they never mutate Cargo's output directory.
Every artifact also contains the root `LICENSE-MIT` and `LICENSE-APACHE` plus
the bundled-font notice, OFL, and Symbols Nerd Font MIT license.

Saved credentials use the freedesktop Secret Service over the user's desktop
D-Bus session. A Secret Service provider such as GNOME Keyring or KWallet must
be running and its default collection must be unlocked. The binaries embed their
D-Bus client library, so no additional client-side shared library is required;
Linux package formats do not declare one particular provider because desktop
environments supply different compatible implementations.

`conmanctl` uses the same Secret Service entries as the GUI. When invoked from
SSH, a service, container, or another headless environment it must be given a
working user D-Bus session and Secret Service provider. Otherwise it fails with
an actionable error instead of silently placing credentials in an ephemeral
kernel keyring.

```sh
scripts/package/linux/build-portable-container.sh
```

This builds on a reproducible Debian 12 glibc baseline in a digest-pinned Rust
container. The wrapper derives a local builder-image tag from the checked-in
Containerfile, so OS packages, Rust 1.96.0, and Zig 0.15.2 are provisioned once
and reused until that definition changes. It runs the repository release
finalizer (including UPX and its integrity/version checks), then creates the
DEB, RPM, AppImage, and generic Linux tar archive from that one finalized
stage:

```sh
scripts/package/linux/build-portable-container.sh dist/packages
```

The DEB and RPM install both programs in `/usr/bin`, plus the desktop entry,
AppStream metadata, and icon. Build native packages on the oldest distribution
release supported by the release; package metadata cannot make a binary built
against a newer glibc run on an older one.

The AppImage contains both programs. It launches ConMan normally and provides
the following CLI workflow:

```sh
./ConMan-*.AppImage --conmanctl --version
./ConMan-*.AppImage --install-cli       # installs to ~/.local/bin/conmanctl
./ConMan-*.AppImage --uninstall-cli
```

`build-appimage.sh` uses `linuxdeploy` and `appimagetool`. Set
`LINUXDEPLOY`/`APPIMAGETOOL` to vetted local copies; otherwise it downloads the
official continuous AppImage builds into `TOOLS_DIR`.

Cargo sources, target outputs, UPX, and AppImage tools are stored outside the
checkout so workspace cleanup does not turn every package job into a cold
build. CI uses `RUNNER_TOOL_CACHE`; local builds use
`${XDG_CACHE_HOME:-$HOME/.cache}/conman/linux-packaging`. Set
`CONMAN_LINUX_CACHE_ROOT` to choose another root. Debian and musl keep distinct
target directories but intentionally share Cargo's target-independent registry
and source cache.

## Static archive

The static archive builder deliberately refuses ordinary dynamically linked
release binaries:

```sh
scripts/package/linux/build-static-container.sh
```

This builds both programs natively in a cached Alpine/musl builder image,
proves that neither ELF has an interpreter nor `DT_NEEDED` entries, and then creates
`conman-<version>-linux-<arch>-static.tar.gz`. “Static” describes the ELF
binaries, not an embedded desktop: a graphical application still needs a
running display server and working host graphics/input services.

The static release disables link-time optimization and uses 16 code-generation
units. Its modest size cost is intentional: the workspace's size-focused
release profile makes this final fully static link disproportionately slow
without changing its portability.
