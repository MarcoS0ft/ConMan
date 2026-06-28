<#
.SYNOPSIS
    Bootstrap the EXACT Zig toolchain libghostty-vt-sys needs (0.15.2) on Windows.

.DESCRIPTION
    The pinned Ghostty commit rejects Zig 0.16.0 (winget ships 0.16.0 — WRONG here).
    Downloads Zig 0.15.2 to a project-local .zig\ directory and prints how to put it
    on PATH. Idempotent: reuses an existing correct copy. No network in build.rs.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\bootstrap-zig.ps1
    # then, as printed:
    $env:PATH = "<repo>\.zig\zig-x86_64-windows-0.15.2;$env:PATH"
#>
$ErrorActionPreference = "Stop"
$ZigVersion = "0.15.2"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DestRoot = Join-Path $RepoRoot ".zig"

function Show-Result($dir) {
    Write-Host ""
    Write-Host "Zig $ZigVersion ready at: $dir"
    Write-Host "Add it to PATH for this shell:"
    Write-Host "    `$env:PATH = `"$dir;`$env:PATH`""
}

# 1. Already correct on PATH?
$zigCmd = Get-Command zig -ErrorAction SilentlyContinue
if ($zigCmd) {
    $have = (& $zigCmd.Source version) 2>$null
    if ($have -eq $ZigVersion) {
        Write-Host "Zig $ZigVersion already on PATH ($($zigCmd.Source)). Nothing to do."
        return
    }
    Write-Host "Note: 'zig' on PATH is $have (need $ZigVersion); installing a project-local copy."
}

# 2. Target triple (Windows; arch from the OS).
$arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $arch = "aarch64" }
$triple = "$arch-windows"
$name = "zig-$triple-$ZigVersion"
$zigDir = Join-Path $DestRoot $name
$zigExe = Join-Path $zigDir "zig.exe"

# 3. Already downloaded?
if ((Test-Path $zigExe) -and ((& $zigExe version) 2>$null) -eq $ZigVersion) {
    Show-Result $zigDir
    return
}

# 4. Download + verify + extract.
$url = "https://ziglang.org/download/$ZigVersion/$name.zip"
New-Item -ItemType Directory -Force -Path $DestRoot | Out-Null
$zip = Join-Path $DestRoot "$name.zip"
Write-Host "Downloading $url ..."
Invoke-WebRequest -Uri $url -OutFile $zip

# Verify sha256 against the official index.
try {
    $index = Invoke-RestMethod -Uri "https://ziglang.org/download/index.json"
    $want = $index.$ZigVersion.$triple.shasum
    if ($want) {
        $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
        if ($got -ne $want.ToLower()) {
            Remove-Item $zip -Force
            throw "sha256 mismatch for $name.zip (expected $want, got $got)"
        }
        Write-Host "sha256 verified."
    }
    else { Write-Host "Warning: could not read expected sha256 from the index; skipping verification." }
}
catch { Write-Host "Warning: checksum verification skipped: $_" }

Write-Host "Extracting ..."
if (Test-Path $zigDir) { Remove-Item -Recurse -Force $zigDir }
# tar (bsdtar) ships with Windows 10+ and extracts the zip far faster than Expand-Archive.
tar -xf $zip -C $DestRoot
Remove-Item $zip -Force

# 5. Confirm and report.
$gotVer = (& $zigExe version) 2>$null
if ($gotVer -ne $ZigVersion) { throw "Extracted Zig reports '$gotVer', expected $ZigVersion." }
Show-Result $zigDir
