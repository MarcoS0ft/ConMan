[CmdletBinding()]
param(
    [Parameter()]
    [string] $CacheDir = ".cache/velopack",

    [Parameter()]
    [string] $PackagePath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repo = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
$toolchain = Get-Content -LiteralPath (Join-Path $repo "packaging/windows/velopack-toolchain.json") -Raw | ConvertFrom-Json
if ($toolchain.version -ne "1.2.0") { throw "This bootstrapper is pinned to Velopack 1.2.0" }

$cache = if ([IO.Path]::IsPathRooted($CacheDir)) { $CacheDir } else { Join-Path $repo $CacheDir }
$cache = [IO.Path]::GetFullPath($cache)
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$package = if ($PackagePath) { $PackagePath } else { Join-Path $cache $toolchain.package }
if (-not (Test-Path -LiteralPath $package -PathType Leaf)) {
    $partial = "$package.partial"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    Invoke-WebRequest -UseBasicParsing -Uri $toolchain.url -OutFile $partial
    Move-Item -LiteralPath $partial -Destination $package
}
$hash = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $toolchain.sha256) { throw "Velopack checksum mismatch: expected $($toolchain.sha256), got $hash" }
Write-Output "VPK_PACKAGE=$((Resolve-Path -LiteralPath $package).Path)"
Write-Output "VPK_SHA256=$hash"
