# ConMan Linux packages

Linux has four distribution formats. All package builders consume an already
built `conman` and `conmanctl`; they never mutate Cargo's output directory.
Every artifact also contains the root `LICENSE-MIT` and `LICENSE-APACHE` plus
the bundled-font notice, OFL, and Symbols Nerd Font MIT license.

```sh
scripts/package/linux/build-portable-container.sh
```

This builds on a reproducible Debian 12 glibc baseline in a digest-pinned Rust
container. It runs the repository release finalizer (including UPX and its
integrity/version checks), then creates the DEB, RPM, AppImage, and generic
Linux tar archive from that one finalized stage:

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

## Static archive

The static archive builder deliberately refuses ordinary dynamically linked
release binaries:

```sh
scripts/package/linux/build-static-container.sh
```

This builds both programs natively in Alpine/musl, proves that neither ELF has
an interpreter nor `DT_NEEDED` entries, and then creates
`conman-<version>-linux-<arch>-static.tar.gz`. “Static” describes the ELF
binaries, not an embedded desktop: a graphical application still needs a
running display server and working host graphics/input services.
