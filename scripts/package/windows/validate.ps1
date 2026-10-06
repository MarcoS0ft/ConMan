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
function Existing([string] $Path) {
    $candidate = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $repo $Path }
    return (Resolve-Path -LiteralPath ([IO.Path]::GetFullPath($candidate))).Path
}
$stage = Existing $StageDir
$output = Existing $OutputDir
$metadata = Get-Content -LiteralPath (Join-Path $stage "release-metadata.json") -Raw | ConvertFrom-Json
$base = "conman-$($metadata.sanitized_version)-windows-x86_64"

function Optional-Property {
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)] [string] $Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}
# Build the exact expected names without accepting arbitrary executable or MSI
# output from the tool. A Velopack full nupkg is the only installed-update asset; Setup
# and MSI are initial-install artifacts and are never independently selected.
$metadataChannel = Optional-Property -Object $metadata -Name "channel"
$channel = if ($metadataChannel) { [string]$metadataChannel } elseif ($metadata.version -match "-dev(?:[.+-]|$)") { "dev" } else { "stable" }
$expected = @(
    "$base.zip", "$base.zip.sha256",
    "$base-$channel-full.nupkg", "$base-$channel-full.nupkg.sha256",
    "$base-$channel-setup.exe", "$base-$channel-setup.exe.sha256",
    "$base-$channel.msi", "$base-$channel.msi.sha256"
)
foreach ($name in $expected) {
    $path = Join-Path $output $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Expected Windows artifact missing: $path" }
    if ((Get-Item -LiteralPath $path).Length -eq 0) { throw "Windows artifact is empty: $path" }
}
foreach ($name in @("$base.zip", "$base-$channel-full.nupkg", "$base-$channel-setup.exe", "$base-$channel.msi")) {
    $artifact = Join-Path $output $name
    $checksum = "$artifact.sha256"
    $line = (Get-Content -LiteralPath $checksum -Raw).Trim()
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Malformed SHA-256 file: $checksum" }
    $actual = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Matches[1] -or $Matches[2] -cne $name) { throw "Checksum mismatch or wrong name for $artifact" }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $output "$base.zip"))
try {
    $members = @($archive.Entries | ForEach-Object { $_.FullName })
    $zipExpected = @(
        "$base/conman.exe", "$base/conmanctl.exe", "$base/ghostty-vt.dll",
        "$base/licenses/LICENSE-MIT", "$base/licenses/LICENSE-APACHE",
        "$base/licenses/NOTICE.md", "$base/licenses/JetBrainsMono-OFL.txt",
        "$base/licenses/SymbolsNerdFont-LICENSE-MIT.txt"
    )
    $difference = Compare-Object -ReferenceObject $zipExpected -DifferenceObject $members
    if ($difference) { throw "Portable ZIP contents differ from the required runtime set: $($difference | Out-String)" }
} finally { $archive.Dispose() }

# Inspect the nupkg payload itself. This protects the package lineage from an
# accidental extra helper/config/cache file and proves that conmanctl remains
# beside its bundled runtime only where the package layout requires it.
$nupkg = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $output "$base-$channel-full.nupkg"))
try {
    $payload = @($nupkg.Entries | Where-Object { -not $_.FullName.EndsWith('/') } | ForEach-Object { $_.FullName })
    $requiredPayload = @(
        "lib/app/conman.exe", "lib/app/ghostty-vt.dll", "lib/app/bin/conmanctl.exe",
        "lib/app/licenses/LICENSE-MIT", "lib/app/licenses/LICENSE-APACHE",
        "lib/app/licenses/NOTICE.md", "lib/app/licenses/JetBrainsMono-OFL.txt",
        "lib/app/licenses/SymbolsNerdFont-LICENSE-MIT.txt"
    )
    foreach ($required in $requiredPayload) {
        if ($required -notin $payload) { throw "Velopack package payload missing $required" }
    }
    # These are the only files vpk 1.2.0 is allowed to add around the exact
    # application payload. In particular, config/database/credential/cache
    # files must never become versioned package content by accident.
    $allowedPayload = @(
        "[Content_Types].xml", "com.marcos0ft.conman.nuspec", "setup.ico", "_rels/.rels",
        "lib/app/conman_ExecutionStub.exe", "lib/app/conman.exe", "lib/app/ghostty-vt.dll",
        "lib/app/sq.version", "lib/app/Squirrel.exe", "lib/app/bin/conmanctl.exe",
        "lib/app/licenses/LICENSE-MIT", "lib/app/licenses/LICENSE-APACHE",
        "lib/app/licenses/NOTICE.md", "lib/app/licenses/JetBrainsMono-OFL.txt",
        "lib/app/licenses/SymbolsNerdFont-LICENSE-MIT.txt"
    )
    $unexpected = @($payload | Where-Object { $_ -notin $allowedPayload })
    if ($unexpected.Count -ne 0) {
        throw "Velopack package contains unexplained members: $($unexpected -join ', ')"
    }
} finally { $nupkg.Dispose() }

Write-Output "VALIDATED=$output"
