[CmdletBinding()]
param(
    [Parameter()]
    [string] $StageDir = "dist/stage",

    [Parameter()]
    [string] $OutputDir = "dist/packages",

    [Parameter()]
    [string] $Python = "py",

    [Parameter()]
    [string] $MakeNsis
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
function Resolve-RepositoryPath {
    param([Parameter(Mandatory)] [string] $Path, [switch] $MustExist)

    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path $repo $Path
    }
    $full = [System.IO.Path]::GetFullPath($candidate)
    if ($MustExist) {
        return (Resolve-Path -LiteralPath $full).Path
    }
    return $full
}

$stage = Resolve-RepositoryPath -Path $StageDir -MustExist
$output = Resolve-RepositoryPath -Path $OutputDir
$metadataPath = Join-Path $stage "release-metadata.json"

if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
    throw "Release metadata not found: $metadataPath"
}
$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
if ($metadata.platform -ne "windows-x86_64") {
    throw "Expected windows-x86_64 release metadata, got '$($metadata.platform)'"
}
if ($metadata.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
    throw "Invalid release version in metadata: '$($metadata.version)'"
}
if ($metadata.sanitized_version -notmatch '^[0-9A-Za-z._-]+$') {
    throw "Invalid artifact version in metadata: '$($metadata.sanitized_version)'"
}

foreach ($name in @("conman.exe", "conmanctl.exe", "ghostty-vt.dll")) {
    $path = Join-Path $stage $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required staged file not found: $path"
    }
}

New-Item -ItemType Directory -Path $output -Force | Out-Null

# Keep the portable archive format and checksum single-sourced in the existing
# cross-platform distribution script.
$packageScript = Join-Path $repo "scripts/dist/package_release.py"
if ($Python -eq "py") {
    & $Python -3 $packageScript --stage-dir $stage --output-dir $output
} else {
    & $Python $packageScript --stage-dir $stage --output-dir $output
}
if ($LASTEXITCODE -ne 0) {
    throw "Portable ZIP creation failed with exit code $LASTEXITCODE"
}

if (-not $MakeNsis) {
    $command = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        $command = Get-Command makensis -ErrorAction SilentlyContinue
    }
    if ($command) {
        $MakeNsis = $command.Source
    } else {
        $MakeNsis = @(
            "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
            "$env:ProgramFiles\NSIS\makensis.exe"
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    }
}
if (-not $MakeNsis -or -not (Test-Path -LiteralPath $MakeNsis -PathType Leaf)) {
    throw "makensis was not found; install NSIS 3 or pass -MakeNsis"
}

$installer = Join-Path $output "conman-$($metadata.sanitized_version)-windows-x86_64-setup.exe"
$definition = Join-Path $repo "packaging/windows/conman.nsi"
& $MakeNsis "/DPRODUCT_VERSION=$($metadata.version)" "/DSTAGE_DIR=$stage" "/DOUTPUT_FILE=$installer" $definition
if ($LASTEXITCODE -ne 0) {
    throw "NSIS packaging failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "NSIS completed without producing $installer"
}
$installerHash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
$installerChecksum = "$installer.sha256"
Set-Content -LiteralPath $installerChecksum -Encoding utf8 -NoNewline `
    -Value "$installerHash  $(Split-Path $installer -Leaf)`n"

& (Join-Path $PSScriptRoot "validate.ps1") -StageDir $stage -OutputDir $output
if ($LASTEXITCODE -ne 0) {
    throw "Windows package validation failed with exit code $LASTEXITCODE"
}

Write-Output "INSTALLER=$installer"
Write-Output "INSTALLER_CHECKSUM=$installerChecksum"
