[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Installer,

    [Parameter()]
    [ValidateSet("Setup", "Msi")]
    [string] $InstallerKind = "Setup",

    [Parameter(Mandatory)]
    [ValidateSet("CurrentUser", "AllUsers")]
    [string] $InstallMode,

    [Parameter(Mandatory)]
    [string] $InstallDir
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$installRoot = [IO.Path]::GetFullPath($InstallDir)
$repo = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
if (Test-Path -LiteralPath $installRoot) { throw "Refusing to reuse an existing smoke directory: $installRoot" }

# Velopack's per-user Setup deliberately chooses the standard LocalAppData
# root. The per-machine MSI receives an explicit root so silent tests cannot
# fall back to a drive-root directory (the W0 physical-host finding).
$expectedRoot = if ($InstallerKind -eq "Setup") {
    if ($InstallMode -ne "CurrentUser") { throw "Velopack Setup smoke must use CurrentUser" }
    [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "com.marcos0ft.conman"))
} else { $installRoot }
if (Test-Path -LiteralPath $expectedRoot) {
    throw "Refusing to touch an existing Velopack installation during smoke test: $expectedRoot"
}
$environmentTarget = if ($InstallMode -eq "AllUsers") { "Machine" } else { "User" }
$payloadRoot = Join-Path $expectedRoot "current"
$installed = $false
$msiProductCode = $null

function Get-PathRegistrySnapshot {
    param([Parameter(Mandatory)] [ValidateSet("User", "Machine")] [string] $Target)

    $hive = if ($Target -eq "Machine") {
        [Microsoft.Win32.RegistryHive]::LocalMachine
    } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        $hive,
        [Microsoft.Win32.RegistryView]::Registry64
    )
    $key = $base.OpenSubKey("Environment", $false)
    try {
        if ($null -eq $key -or $null -eq $key.GetValueNames() -or -not ($key.GetValueNames() -contains "Path")) {
            return [pscustomobject]@{ Exists = $false; Value = $null; Kind = $null }
        }
        $kind = $key.GetValueKind("Path").ToString()
        if ($kind -notin @("String", "ExpandString")) {
            throw "$Target PATH has unsupported registry type $kind"
        }
        $value = $key.GetValue(
            "Path",
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        if ($value -isnot [string]) { throw "$Target PATH registry value is not a string" }
        return [pscustomobject]@{ Exists = $true; Value = [string]$value; Kind = $kind }
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

$pathBeforeSnapshot = Get-PathRegistrySnapshot $environmentTarget

function Test-PathEntry {
    param([AllowNull()] [string] $Value, [string] $Entry)
    if (-not $Value) { return $false }
    return [bool]($Value.Split(';') | Where-Object { $_.Trim().Equals($Entry, [StringComparison]::OrdinalIgnoreCase) })
}

try {
    if ($InstallerKind -eq "Setup") {
        $installProcess = Start-Process -FilePath $installerPath -ArgumentList @("/silent") -Wait -PassThru
    } else {
        $arguments = @(
            "/i", "`"$installerPath`"", "VELOPACK_INSTALLDIR=`"$installRoot`"", "/qn", "/norestart"
        )
        $installProcess = Start-Process -FilePath "msiexec.exe" -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    }
    if ($installProcess.ExitCode -ne 0) { throw "Velopack installer exited with status $($installProcess.ExitCode)" }
    $installed = $true

    foreach ($name in @("conman.exe", "ghostty-vt.dll", "bin\conmanctl.exe", "licenses\LICENSE-MIT", "licenses\LICENSE-APACHE", "licenses\NOTICE.md", "licenses\JetBrainsMono-OFL.txt", "licenses\SymbolsNerdFont-LICENSE-MIT.txt")) {
        $path = Join-Path $payloadRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Installed payload missing: $path" }
    }
    $pathDuring = [Environment]::GetEnvironmentVariable("Path", $environmentTarget)
    if (-not (Test-PathEntry $pathDuring (Join-Path $payloadRoot "bin"))) { throw "Velopack PATH hook did not add $payloadRoot\bin" }
    & (Join-Path $payloadRoot "bin\conmanctl.exe") --version | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Installed conmanctl --version failed with status $LASTEXITCODE" }

    $shortcutRoot = if ($InstallMode -eq "AllUsers") {
        [Environment]::GetFolderPath("CommonPrograms")
    } else { [Environment]::GetFolderPath("Programs") }
    $shell = New-Object -ComObject WScript.Shell
    $shortcuts = @(Get-ChildItem -LiteralPath $shortcutRoot -Filter "*.lnk" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            try { $shell.CreateShortcut($_.FullName).TargetPath -ieq (Join-Path $payloadRoot "conman.exe") }
            catch { $false }
        })
    if ($shortcuts.Count -ne 1) { throw "Expected exactly one ConMan Start Menu shortcut, found $($shortcuts.Count)" }

    $arpHive = if ($InstallMode -eq "AllUsers") { "HKLM:" } else { "HKCU:" }
    $arpBase = Join-Path $arpHive "Software\Microsoft\Windows\CurrentVersion\Uninstall"
    $arpMatches = @(Get-ChildItem -LiteralPath $arpBase -ErrorAction SilentlyContinue |
        Where-Object {
            $displayName = (Get-ItemProperty -LiteralPath $_.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
            $displayName -eq "Connection Manager"
        })
    if ($arpMatches.Count -ne 1) { throw "Expected one ConMan Add/Remove Programs entry, found $($arpMatches.Count)" }
    if ($InstallerKind -eq "Msi") { $msiProductCode = [string]$arpMatches[0].PSChildName }
} finally {
    if ($installed) {
        if ($InstallerKind -eq "Msi" -and $msiProductCode) {
            $uninstall = Start-Process -FilePath "msiexec.exe" -Verb RunAs -ArgumentList @(
                "/x", $msiProductCode, "/qn", "/norestart"
            ) -Wait -PassThru
            if ($uninstall.ExitCode -ne 0) { Write-Error "MSI uninstall exited with status $($uninstall.ExitCode)" }
        } else {
            $uninstaller = Join-Path $expectedRoot "Update.exe"
            if (-not (Test-Path -LiteralPath $uninstaller)) { $uninstaller = Join-Path $expectedRoot "current\Update.exe" }
            if (Test-Path -LiteralPath $uninstaller) {
                $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @("uninstall", "--silent") -Wait -PassThru
                if ($uninstall.ExitCode -ne 0) { Write-Error "Velopack uninstall exited with status $($uninstall.ExitCode)" }
            }
        }
    }
}

if (Test-Path -LiteralPath $expectedRoot) { throw "Velopack uninstall left the installation root behind: $expectedRoot" }
$pathAfterSnapshot = Get-PathRegistrySnapshot $environmentTarget
if (Test-PathEntry $pathAfterSnapshot.Value (Join-Path $payloadRoot "bin")) { throw "Velopack uninstall left its PATH entry behind" }
if ($pathAfterSnapshot.Exists -ne $pathBeforeSnapshot.Exists -or
    $pathAfterSnapshot.Kind -cne $pathBeforeSnapshot.Kind -or
    $pathAfterSnapshot.Value -cne $pathBeforeSnapshot.Value) {
    throw "Velopack smoke test did not restore PATH text, registry type, and missing-value state byte-for-byte"
}

$shortcutRoot = if ($InstallMode -eq "AllUsers") {
    [Environment]::GetFolderPath("CommonPrograms")
} else { [Environment]::GetFolderPath("Programs") }
$shell = New-Object -ComObject WScript.Shell
$leftoverShortcuts = @(Get-ChildItem -LiteralPath $shortcutRoot -Filter "*.lnk" -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        try { $shell.CreateShortcut($_.FullName).TargetPath -ieq (Join-Path $payloadRoot "conman.exe") }
        catch { $false }
})
if ($leftoverShortcuts.Count -ne 0) { throw "Velopack uninstall left a ConMan Start Menu shortcut behind" }
$arpHive = if ($InstallMode -eq "AllUsers") { "HKLM:" } else { "HKCU:" }
$arpBase = Join-Path $arpHive "Software\Microsoft\Windows\CurrentVersion\Uninstall"
$leftoverArp = @(Get-ChildItem -LiteralPath $arpBase -ErrorAction SilentlyContinue |
    Where-Object {
        $displayName = (Get-ItemProperty -LiteralPath $_.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
        $displayName -eq "Connection Manager"
    })
if ($leftoverArp.Count -ne 0) { throw "Velopack uninstall left a ConMan Add/Remove Programs entry behind" }

Write-Output "INSTALLER_KIND=$InstallerKind"
Write-Output "INSTALL_SMOKE_OK=$InstallMode"
