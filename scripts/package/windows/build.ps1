[CmdletBinding()]
param(
    [Parameter()]
    [string] $StageDir = "dist/stage",

    [Parameter()]
    [string] $OutputDir = "dist/packages",

    [Parameter()]
    [string] $VpkPath,

    [Parameter()]
    [string] $DotNetPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
function Resolve-RepositoryPath {
    param([Parameter(Mandatory)] [string] $Path, [switch] $MustExist)

    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $repo $Path }
    $full = [System.IO.Path]::GetFullPath($candidate)
    if ($MustExist) { return (Resolve-Path -LiteralPath $full).Path }
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

$toolchain = Get-Content -LiteralPath (Join-Path $repo "packaging/windows/velopack-toolchain.json") -Raw | ConvertFrom-Json
if ($toolchain.version -ne "1.2.0") { throw "This packaging script is pinned to Velopack 1.2.0" }

function Optional-Property {
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)] [string] $Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Resolve-Vpk {
    param([string] $RequestedPath)

    $path = $RequestedPath
    if (-not $path) { $path = $env:CONMAN_VPK_PATH }
    if (-not $path) { $path = Join-Path $repo ".cache/velopack/vpk.1.2.0.nupkg" }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Pinned Velopack package/tool not found: $path. Run bootstrap-velopack.ps1 or pass -VpkPath."
    }
    $resolved = (Resolve-Path -LiteralPath $path).Path
    $actualHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    $acceptedHashes = @([string]$toolchain.sha256)
    $exeHash = Optional-Property -Object $toolchain -Name "exe_sha256"
    if ($exeHash) { $acceptedHashes += [string]$exeHash }
    if ($actualHash -notin $acceptedHashes) {
        throw "Velopack 1.2.0 checksum mismatch: expected $($acceptedHashes -join ', '), got $actualHash"
    }
    if ([IO.Path]::GetExtension($resolved) -ieq ".exe") {
        return [pscustomobject]@{ File = $resolved; Prefix = @() }
    }
    if ([IO.Path]::GetExtension($resolved) -ine ".nupkg") {
        throw "-VpkPath must identify the pinned vpk.exe or vpk.1.2.0.nupkg"
    }
    $extract = Join-Path ([IO.Path]::GetTempPath()) ("conman-vpk-1.2.0-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $extract | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($resolved, $extract)
    $dll = Get-ChildItem -LiteralPath $extract -Filter "vpk.dll" -Recurse -File |
        Where-Object { $_.FullName -match "[\\/]tools[\\/]net8\.0[\\/]any[\\/]vpk\.dll$" } |
        Select-Object -First 1
    if (-not $dll) { throw "Pinned vpk package contains no net8.0 vpk.dll" }
    $dotnet = if ($DotNetPath) { $DotNetPath } else { (Get-Command dotnet.exe -ErrorAction SilentlyContinue).Source }
    if (-not $dotnet -or -not (Test-Path -LiteralPath $dotnet -PathType Leaf)) {
        throw "dotnet 8 is required to run pinned Velopack vpk.dll"
    }
    $version = (& $dotnet --version).Trim()
    if ($version -notmatch '^8\.') { throw "Pinned vpk.dll requires dotnet 8; found '$version'" }
    return [pscustomobject]@{ File = $dll.FullName; Prefix = @($dotnet) }
}

function Invoke-Vpk {
    param([Parameter(Mandatory)] $Command, [Parameter(Mandatory)] [string[]] $Arguments)
    $all = @($Command.Prefix) + @($Command.File) + $Arguments
    & $all[0] $all[1..($all.Count - 1)]
    if ($LASTEXITCODE -ne 0) { throw "Velopack 1.2.0 packaging failed with exit code $LASTEXITCODE" }
}

New-Item -ItemType Directory -Path $output -Force | Out-Null
$vpk = Resolve-Vpk -RequestedPath $VpkPath
$metadataChannel = Optional-Property -Object $metadata -Name "channel"
$metadataMsiVersion = Optional-Property -Object $metadata -Name "msi_version"
$channel = if ($metadataChannel) { [string]$metadataChannel } elseif ($metadata.version -match "-dev(?:[.+-]|$)") { "dev" } else { "stable" }
if ($channel -notin @("stable", "dev")) { throw "Expected release channel stable or dev, got '$channel'" }
$msiVersion = if ($metadataMsiVersion) { [string]$metadataMsiVersion } elseif ($metadata.version -match '^([0-9]+)\.([0-9]+)\.([0-9]+)') { "$($Matches[1]).$($Matches[2]).$($Matches[3]).0" } else { throw "Could not derive MSI version" }
if ($msiVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') { throw "Invalid MSI version '$msiVersion'" }

$velopackStage = Join-Path ([IO.Path]::GetTempPath()) ("conman-velopack-stage-" + [guid]::NewGuid().ToString("N"))
$velopackOutput = Join-Path ([IO.Path]::GetTempPath()) ("conman-velopack-output-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $velopackStage "bin"), (Join-Path $velopackStage "licenses"), $velopackOutput | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $stage "conman.exe") -Destination $velopackStage
    Copy-Item -LiteralPath (Join-Path $stage "ghostty-vt.dll") -Destination $velopackStage
    Copy-Item -LiteralPath (Join-Path $stage "conmanctl.exe") -Destination (Join-Path $velopackStage "bin/conmanctl.exe")
    Copy-Item -LiteralPath (Join-Path $repo "LICENSE-MIT") -Destination (Join-Path $velopackStage "licenses/LICENSE-MIT")
    Copy-Item -LiteralPath (Join-Path $repo "LICENSE-APACHE") -Destination (Join-Path $velopackStage "licenses/LICENSE-APACHE")
    Copy-Item -LiteralPath (Join-Path $repo "crates/cm-ui/assets/fonts/NOTICE.md") -Destination (Join-Path $velopackStage "licenses/NOTICE.md")
    Copy-Item -LiteralPath (Join-Path $repo "crates/cm-ui/assets/fonts/JetBrainsMono-OFL.txt") -Destination (Join-Path $velopackStage "licenses/JetBrainsMono-OFL.txt")
    Copy-Item -LiteralPath (Join-Path $repo "crates/cm-ui/assets/fonts/SymbolsNerdFont-LICENSE-MIT.txt") -Destination (Join-Path $velopackStage "licenses/SymbolsNerdFont-LICENSE-MIT.txt")
    Invoke-Vpk -Command $vpk -Arguments @(
        "pack", "--packId", "com.marcos0ft.conman", "--packVersion", [string]$metadata.version,
        "--packDir", $velopackStage, "--mainExe", "conman.exe", "--packAuthors", "MarcoS0ft",
        "--packTitle", "Connection Manager", "--icon", (Join-Path $repo "resources/ConMan.ico"),
        "--shortcuts", "StartMenuRoot", "--channel", $channel, "--runtime", "win-x64",
        "--delta", "None", "--msi", "true", "--msiVersion", $msiVersion, "--instLocation", "Either",
        "--outputDir", $velopackOutput, "--yes", "true", "--skip-updates", "true"
    )
    $fullPackages = @(Get-ChildItem -LiteralPath $velopackOutput -Filter "*.nupkg" -File | Where-Object { $_.Name -match "-full\.nupkg$" })
    $setups = @(Get-ChildItem -LiteralPath $velopackOutput -Filter "*.exe" -File | Where-Object { $_.Name -match "(?i)setup" })
    $msis = @(Get-ChildItem -LiteralPath $velopackOutput -Filter "*.msi" -File)
    if ($fullPackages.Count -ne 1 -or $setups.Count -ne 1 -or $msis.Count -ne 1) {
        throw "Velopack produced unexpected artifacts (full=$($fullPackages.Count), setup=$($setups.Count), msi=$($msis.Count))"
    }
    $velopackBase = "conman-$($metadata.sanitized_version)-windows-x86_64"
    $full = Join-Path $output "$velopackBase-$channel-full.nupkg"
    $setup = Join-Path $output "$velopackBase-$channel-setup.exe"
    $msi = Join-Path $output "$velopackBase-$channel.msi"
    foreach ($destination in @($full, $setup, $msi)) { if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Force } }
    Move-Item -LiteralPath $fullPackages[0].FullName -Destination $full
    Move-Item -LiteralPath $setups[0].FullName -Destination $setup
    Move-Item -LiteralPath $msis[0].FullName -Destination $msi
    foreach ($artifact in @($full, $setup, $msi)) {
        $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath "$artifact.sha256" -Encoding utf8 -NoNewline -Value "$hash  $(Split-Path $artifact -Leaf)`n"
    }
} finally {
    if (Test-Path -LiteralPath $velopackStage) { Remove-Item -LiteralPath $velopackStage -Recurse -Force }
    if (Test-Path -LiteralPath $velopackOutput) { Remove-Item -LiteralPath $velopackOutput -Recurse -Force }
}

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
foreach ($source in $portableFiles.Values) { if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required portable file not found: $source" } }
$archive = Join-Path $output "$base.zip"
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [System.IO.File]::Open($archive, [System.IO.FileMode]::CreateNew)
$zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($relative in @($portableFiles.Keys | Sort-Object)) {
        $source = $portableFiles[$relative]
        $entry = $zip.CreateEntry("$base/$relative", [System.IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = (Get-Item -LiteralPath $source).LastWriteTime
        $sourceStream = [System.IO.File]::OpenRead($source)
        $entryStream = $entry.Open()
        try { $sourceStream.CopyTo($entryStream) } finally { $entryStream.Dispose(); $sourceStream.Dispose() }
    }
} finally { $zip.Dispose(); $stream.Dispose() }
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -Encoding utf8 -NoNewline -Value "$archiveHash  $(Split-Path $archive -Leaf)`n"

& (Join-Path $PSScriptRoot "validate.ps1") -StageDir $stage -OutputDir $output
if ($LASTEXITCODE -ne 0) { throw "Windows package validation failed with exit code $LASTEXITCODE" }
Write-Output "VELOPACK_FULL=$full"
Write-Output "VELOPACK_SETUP=$setup"
Write-Output "VELOPACK_MSI=$msi"
Write-Output "PORTABLE_ZIP=$archive"
