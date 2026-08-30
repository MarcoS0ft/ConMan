# Windows packages

The Windows release has two equivalent delivery formats:

- `conman-<version>-windows-x86_64-setup.exe` is an NSIS installer. It offers
  per-user and all-users modes, installs the GUI and Ghostty runtime together,
  installs `conmanctl.exe` under `bin`, and adds that `bin` directory to the
  matching user or system `PATH`. Uninstall removes the exact PATH entry.
- `conman-<version>-windows-x86_64.zip` is the standalone distribution containing
  `conman.exe`, `conmanctl.exe`, `ghostty-vt.dll`, and the project/font notices
  under `licenses`.

After `scripts/dist/prepare_release.py` has produced a `windows-x86_64` staging
tree, build and validate both packages from PowerShell:

```powershell
./scripts/package/windows/build.ps1 -StageDir dist/stage -OutputDir dist/packages
```

NSIS 3 must be available. The script also accepts an explicit `-MakeNsis` path
for provisioned runners. Official CI should run
this script after the existing stage/compress/signing boundary, upload the setup
executable and both SHA-256 files alongside the ZIP, and never use
machine-specific paths.

The opt-in installation smoke test exercises either scope, including payload,
Start menu, Add/Remove Programs, PATH, CLI startup, and clean uninstall. Give it
a new, narrow scratch directory that does not already exist:

```powershell
./scripts/package/windows/install-smoke.ps1 `
  -Installer dist/packages/conman-<version>-windows-x86_64-setup.exe `
  -InstallMode CurrentUser `
  -InstallDir dist/install-smoke-current-user
```
