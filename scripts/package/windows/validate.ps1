[CmdletBinding()]
param(
    [Parameter()]
    [string] $StageDir = "dist/stage",

    [Parameter()]
    [string] $OutputDir = "dist/packages"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
function Resolve-ExistingRepositoryPath {
    param([Parameter(Mandatory)] [string] $Path)

    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path $repo $Path
    }
    return (Resolve-Path -LiteralPath ([System.IO.Path]::GetFullPath($candidate))).Path
}

$stage = Resolve-ExistingRepositoryPath -Path $StageDir
$output = Resolve-ExistingRepositoryPath -Path $OutputDir
$metadata = Get-Content -LiteralPath (Join-Path $stage "release-metadata.json") -Raw | ConvertFrom-Json
$base = "conman-$($metadata.sanitized_version)-windows-x86_64"
$archive = Join-Path $output "$base.zip"
$checksumFile = "$archive.sha256"
$installer = Join-Path $output "$base-setup.exe"
$installerChecksumFile = "$installer.sha256"

foreach ($file in @($archive, $checksumFile, $installer, $installerChecksumFile)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Expected Windows package not found: $file"
    }
    if ((Get-Item -LiteralPath $file).Length -eq 0) {
        throw "Windows package is empty: $file"
    }
}

foreach ($pair in @(
    @($archive, $checksumFile),
    @($installer, $installerChecksumFile)
)) {
    $artifact = $pair[0]
    $artifactChecksum = $pair[1]
    $checksumLine = (Get-Content -LiteralPath $artifactChecksum -Raw).Trim()
    if ($checksumLine -notmatch '^([0-9a-f]{64})  (.+)$') {
        throw "Malformed SHA-256 file: $artifactChecksum"
    }
    $expectedHash = $Matches[1]
    $expectedName = $Matches[2]
    $actualHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Checksum mismatch for ${artifact}: expected $expectedHash, got $actualHash"
    }
    if ($expectedName -ne (Split-Path $artifact -Leaf)) {
        throw "Checksum names '$expectedName' instead of '$(Split-Path $artifact -Leaf)'"
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
try {
    $members = @($zip.Entries | ForEach-Object { $_.FullName })
} finally {
    $zip.Dispose()
}
$expected = @(
    "$base/conman.exe",
    "$base/conmanctl.exe",
    "$base/ghostty-vt.dll"
)
$difference = Compare-Object -ReferenceObject $expected -DifferenceObject $members
if ($difference) {
    throw "Portable ZIP contents differ from the required runtime set: $($difference | Out-String)"
}

Write-Output "VALIDATED=$installer"
Write-Output "VALIDATED=$archive"
