[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Installer,

    [Parameter(Mandatory)]
    [ValidateSet("CurrentUser", "AllUsers")]
    [string] $InstallMode,

    [Parameter(Mandatory)]
    [string] $InstallDir
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$installRoot = [System.IO.Path]::GetFullPath($InstallDir)
$repo = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
if (Test-Path -LiteralPath $installRoot) {
    throw "Refusing to reuse an existing installer smoke directory: $installRoot"
}

$environmentTarget = if ($InstallMode -eq "AllUsers") { "Machine" } else { "User" }
$registryHive = if ($InstallMode -eq "AllUsers") { "HKLM:" } else { "HKCU:" }
$startMenuRoot = if ($InstallMode -eq "AllUsers") {
    [Environment]::GetFolderPath("CommonPrograms")
} else {
    [Environment]::GetFolderPath("Programs")
}
$uninstallKey = Join-Path $registryHive "Software\Microsoft\Windows\CurrentVersion\Uninstall\ConMan"
$shortcut = Join-Path $startMenuRoot "Connection Manager.lnk"
$pathBefore = [Environment]::GetEnvironmentVariable("Path", $environmentTarget)
$expectedPathEntry = Join-Path $installRoot "bin"
$installed = $false

function Get-PathEntries {
    param([AllowNull()] [string] $Value)
    if (-not $Value) { return @() }
    return @($Value.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-PathEntry {
    param([AllowNull()] [string] $Value, [string] $Entry)
    return [bool](Get-PathEntries $Value | Where-Object {
        $_.Equals($Entry, [StringComparison]::OrdinalIgnoreCase)
    })
}

function Get-PathFingerprint {
    param([AllowNull()] [string] $Value)
    if ($null -eq $Value) { $Value = "" }
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::Unicode.GetBytes($Value))
    ).ToLowerInvariant()
}

try {
    # NSIS is a GUI-subsystem executable, so direct invocation can return before
    # installation completes. Start-Process -Wait makes every assertion below
    # observe the finished transaction. /D must remain the final NSIS argument.
    $installProcess = Start-Process -FilePath $installerPath `
        -ArgumentList "/S /$InstallMode /D=$installRoot" -Wait -PassThru
    if ($installProcess.ExitCode -ne 0) {
        throw "Installer exited with status $($installProcess.ExitCode) in $InstallMode mode"
    }
    $installed = $true

    foreach ($name in @(
        "conman.exe",
        "ghostty-vt.dll",
        "bin\conmanctl.exe",
        "update-path.ps1",
        "licenses\LICENSE-MIT",
        "licenses\LICENSE-APACHE",
        "licenses\NOTICE.md",
        "licenses\JetBrainsMono-OFL.txt",
        "licenses\SymbolsNerdFont-LICENSE-MIT.txt",
        "Uninstall.exe"
    )) {
        $path = Join-Path $installRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Installed file missing: $path"
        }
    }
    $licenseSources = @{
        "licenses\LICENSE-MIT" = Join-Path $repo "LICENSE-MIT"
        "licenses\LICENSE-APACHE" = Join-Path $repo "LICENSE-APACHE"
        "licenses\NOTICE.md" = Join-Path $repo "crates/cm-ui/assets/fonts/NOTICE.md"
        "licenses\JetBrainsMono-OFL.txt" = Join-Path $repo "crates/cm-ui/assets/fonts/JetBrainsMono-OFL.txt"
        "licenses\SymbolsNerdFont-LICENSE-MIT.txt" = Join-Path $repo "crates/cm-ui/assets/fonts/SymbolsNerdFont-LICENSE-MIT.txt"
    }
    foreach ($relative in $licenseSources.Keys) {
        $installedHash = (Get-FileHash -LiteralPath (Join-Path $installRoot $relative) -Algorithm SHA256).Hash
        $sourceHash = (Get-FileHash -LiteralPath $licenseSources[$relative] -Algorithm SHA256).Hash
        if ($installedHash -ne $sourceHash) {
            throw "Installed license differs from its authoritative source: $relative"
        }
    }
    if (-not (Test-Path -LiteralPath $uninstallKey)) {
        throw "Add/Remove Programs key missing: $uninstallKey"
    }
    if (-not (Test-Path -LiteralPath $shortcut -PathType Leaf)) {
        throw "Start menu shortcut missing: $shortcut"
    }

    $pathDuring = [Environment]::GetEnvironmentVariable("Path", $environmentTarget)
    if (-not (Test-PathEntry $pathDuring $expectedPathEntry)) {
        throw "$expectedPathEntry was not added to the $environmentTarget PATH"
    }

    & (Join-Path $installRoot "bin\conmanctl.exe") --version | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Installed conmanctl --version failed with status $LASTEXITCODE"
    }
}
finally {
    if ($installed) {
        $uninstaller = Join-Path $installRoot "Uninstall.exe"
        if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
            $uninstallProcess = Start-Process -FilePath $uninstaller `
                -ArgumentList "/S /$InstallMode" -Wait -PassThru
            if ($uninstallProcess.ExitCode -ne 0) {
                Write-Error "Uninstaller exited with status $($uninstallProcess.ExitCode)"
            }
        }
    }
}

if (Test-Path -LiteralPath $installRoot) {
    throw "Uninstaller left the installation directory behind: $installRoot"
}
if (Test-Path -LiteralPath $uninstallKey) {
    throw "Uninstaller left the Add/Remove Programs key behind: $uninstallKey"
}
if (Test-Path -LiteralPath $shortcut) {
    throw "Uninstaller left the Start menu shortcut behind: $shortcut"
}
$pathAfter = [Environment]::GetEnvironmentVariable("Path", $environmentTarget)
if (Test-PathEntry $pathAfter $expectedPathEntry) {
    throw "Uninstaller left $expectedPathEntry on the $environmentTarget PATH"
}

if ($pathAfter -cne $pathBefore) {
    throw "Installer smoke test did not restore the $environmentTarget PATH byte-for-byte"
}

Write-Output "PATH_BEFORE_UTF16_SHA256=$(Get-PathFingerprint $pathBefore)"
Write-Output "PATH_AFTER_UTF16_SHA256=$(Get-PathFingerprint $pathAfter)"
Write-Output "PATH_ENTRY_COUNT=$(@(Get-PathEntries $pathAfter).Count)"
Write-Output "INSTALL_SMOKE_OK=$InstallMode"
