# Windows packages

The installed Windows lineage is Velopack 1.2.0:

- `conman-<version>-windows-x86_64-<channel>-setup.exe` is the per-user
  one-click Setup. It installs under `%LocalAppData%` without UAC.
- `conman-<version>-windows-x86_64-<channel>.msi` is the per-machine package.
  It installs under the explicit Program Files root and requests ordinary UAC.
- `conman-<version>-windows-x86_64-<channel>-full.nupkg` is the full update
  package. It is the only installed-update asset authorized by the signed
  `conman-update.json` manifest; Velopack does not select a channel or version.
- `conman-<version>-windows-x86_64.zip` is the standalone portable package.
  Portable installs are check/download-only and are never replaced in place.

The full package contains only `conman.exe`, `bin/conmanctl.exe`,
`ghostty-vt.dll`, and the five distribution notices/licenses. Velopack owns its
versioned layout, updater, shortcut, and uninstall registration. ConMan's
Windows hooks own only the exact install-scope PATH fragment and the visible
64-bit MSI ARP version entry. Configuration, SQLite state, credentials, logs,
and update staging remain outside versioned package content.

Velopack is pinned by [velopack-toolchain.json](velopack-toolchain.json),
including the SHA-256 of the `vpk.1.2.0.nupkg` tool. Provision a runner or
bootstrap a local cache with:

```powershell
./scripts/package/windows/bootstrap-velopack.ps1
./scripts/package/windows/build.ps1 -StageDir dist/stage -OutputDir dist/packages
```

Pass `-VpkPath` to the checked tool package or `vpk.exe`. When a package is
passed, the script extracts and executes only its pinned `net8.0/vpk.dll` with
dotnet 8. There is no floating `latest` tool or network feed in the build.

Build after `scripts/dist/prepare_release.py` has finalized the UPX binaries.
Velopack keeps the full SemVer package version. MSI uses
`major.minor.(2 * Git revision + stable)`, where `stable` is `1` for a stable
version and `0` for a development build. For example, development revision 406
is `0.1.812`; a stable `0.1.0` at that revision is `0.1.813`. Patch releases
advance through Git revisions. This changes one of the three fields Windows
Installer actually compares; a fourth field is ignored. Major and minor must
fit `0..255`, and revisions must fit `1..32767`; packaging fails outside those
bounds or when a development binary's revision differs from the checkout.
Validation reads the generated MSI's `ProductVersion` and checks this mapping.

The required signing order remains build -> UPX -> sign shipped executables ->
Velopack package -> optionally sign Setup/MSI. Signing inputs are optional and
must be injected only by a trusted release workflow.

Validate all output with:

```powershell
./scripts/package/windows/validate.ps1 -StageDir dist/stage -OutputDir dist/packages
```

The install smoke test is intentionally opt-in and requires an isolated,
nonexistent scratch directory. It verifies the payload, shortcut, ARP, PATH,
CLI startup, and clean uninstall in either scope:

```powershell
./scripts/package/windows/install-smoke.ps1 `
  -Installer dist/packages/conman-<version>-windows-x86_64-stable-setup.exe `
  -InstallMode CurrentUser `
  -InstallDir dist/install-smoke-current-user
```

Automatic update discovery and download are not yet connected to the application.
The shared manifest generator exists, but release workflows do not yet publish
its manifest/signature assets. See [update status](../../docs/updates.md).
