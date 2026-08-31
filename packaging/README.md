# Release packages

ConMan publishes native packages from the exact Git revision tested by CI. The
reusable release workflow runs only on the organization-owned Linux, macOS, and
Windows runners; tracked workflow files contain no runner hostnames, network
addresses, account names, or machine-specific paths.

## Deliverables

- Linux x86_64: DEB, RPM, AppImage, UPX-compressed portable archive, and a
  separately built static-musl archive containing `conman` and `conmanctl`.
- macOS arm64: a signed `ConMan.app` inside a DMG, with an opt-in installer for
  `/usr/local/bin/conmanctl`. Downloadable rolling builds and stable tags use
  the organization Developer ID and notarization secrets; packaging fails
  rather than publishing an unsigned or unnotarized DMG. Local and disposable
  validation builds may continue to use an explicit ad-hoc signature, but do
  not receive access to production Keychain items.
- Windows x86_64: an NSIS installer supporting per-user and all-users installs,
  plus a portable ZIP. Both include `conmanctl`; the installer adds its scoped
  `bin` directory to the matching `PATH` and removes only its own entry.

Every format includes the project licenses and notices for bundled fonts.
Linux and Windows release executables are compressed with the pinned UPX build
and verified before packaging. macOS executables are never UPX-compressed.
The macOS distribution path signs the nested executables and app with hardened
runtime and secure timestamps, signs the final DMG, submits only that outermost
container to Apple's notary service, staples its ticket, and requires the final
Gatekeeper assessment to pass before the asset can be published.
The GUI and app-like `conmanctl` helper embed distinct Developer ID provisioning
profiles and are signed with one shared Keychain Access Group. Both profiles
are mandatory because Apple authorizes restricted entitlements per executable
bundle; the release scripts never fall back to the legacy file-based Keychain.
CI supplies their base64-encoded contents through the
`CONMAN_MACOS_APP_PROVISIONING_PROFILE` and
`CONMAN_MACOS_CLI_PROVISIONING_PROFILE`
organization secrets; profile files and signing credentials are never stored
in the repository.

## Local entrypoints

Run these commands from the repository root:

```text
scripts/package/linux/build-portable-container.sh dist/packages
scripts/package/linux/build-static-container.sh dist/packages
scripts/package/macos/release.sh --target-dir target/release --output-dir dist/packages --sign-identity -
scripts/package/windows/build.ps1 -StageDir dist/stage -OutputDir dist/packages
```

The Linux entrypoints use digest-pinned baseline containers. The macOS and
Windows entrypoints consume native release binaries. Windows first uses
`scripts/dist/prepare_release.py` to produce its verified staging tree.
Platform-specific prerequisites and validation commands are documented in each
platform directory.
