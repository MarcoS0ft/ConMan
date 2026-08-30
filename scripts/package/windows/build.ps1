[CmdletBinding()]
param(
    [Parameter()]
    [string] $StageDir = "dist/stage",

    [Parameter()]
    [string] $OutputDir = "dist/packages",

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

$base = "conman-$($metadata.sanitized_version)-windows-x86_64"
$portableFiles = [ordered]@{
    "conman.exe" = Join-Path $stage "conman.exe"
    "conmanctl.exe" = Join-Path $stage "conmanctl.exe"
    "ghostty-vt.dll" = Join-Path $stage "ghostty-vt.dll"
    "licenses/LICENSE-MIT" = Join-Path $repo "LICENSE-MIT"
    "licenses/LICENSE-APACHE" = Join-Path $repo "LICENSE-APACHE"
    "licenses/NOTICE.md" = Join-Path $repo "crates/cm-ui/assets/fonts/NOTICE.md"
    "licenses/JetBrainsMono-OFL.txt" = Join-Path $repo "crates/cm-ui/assets/fonts/JetBrainsMono-OFL.txt"
    "licenses/SymbolsNerdFont-LICENSE-MIT.txt" = Join-Path $repo "crates/cm-ui/assets/fonts/SymbolsNerdFont-LICENSE-MIT.txt"
}
foreach ($source in $portableFiles.Values) {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Required portable-package file not found: $source"
    }
}

$archive = Join-Path $output "$base.zip"
if (Test-Path -LiteralPath $archive) {
    [System.IO.File]::Delete($archive)
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [System.IO.File]::Open($archive, [System.IO.FileMode]::CreateNew)
$zip = [System.IO.Compression.ZipArchive]::new(
    $stream,
    [System.IO.Compression.ZipArchiveMode]::Create
)
try {
    foreach ($relative in @($portableFiles.Keys | Sort-Object)) {
        $source = $portableFiles[$relative]
        $entry = $zip.CreateEntry(
            "$base/$relative",
            [System.IO.Compression.CompressionLevel]::Optimal
        )
        $entry.LastWriteTime = (Get-Item -LiteralPath $source).LastWriteTime
        $sourceStream = [System.IO.File]::OpenRead($source)
        $entryStream = $entry.Open()
        try {
            $sourceStream.CopyTo($entryStream)
        } finally {
            $entryStream.Dispose()
            $sourceStream.Dispose()
        }
    }
} finally {
    $zip.Dispose()
    $stream.Dispose()
}
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -Encoding utf8 -NoNewline `
    -Value "$archiveHash  $(Split-Path $archive -Leaf)`n"

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

$installer = Join-Path $output "$base-setup.exe"
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
