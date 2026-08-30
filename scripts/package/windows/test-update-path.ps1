[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$helper = (Resolve-Path (Join-Path $PSScriptRoot "../../../packaging/windows/update-path.ps1")).Path
$entry = "C:\ConMan\bin"
$variable = "CONMAN_PATH_TEST_$PID"

function Invoke-Helper {
    param(
        [Parameter(Mandatory)] [string] $Action,
        [string] $RemoveMode
    )

    $arguments = @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", $helper, "-Action", $Action, "-Scope", "User",
        "-Entry", $entry, "-VariableName", $variable
    )
    if ($RemoveMode) { $arguments += @("-RemoveMode", $RemoveMode) }
    $process = Start-Process -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList $arguments -Wait -PassThru
    return $process.ExitCode
}

function Set-TestValue {
    param([AllowNull()] [string] $Value)
    [Environment]::SetEnvironmentVariable($variable, $Value, "User")
}

function Get-TestValue {
    $value = [Environment]::GetEnvironmentVariable($variable, "User")
    if ($null -eq $value) { return "" }
    return $value
}

function Assert-Equal {
    param([AllowNull()] [string] $Expected, [AllowNull()] [string] $Actual, [string] $Case)
    if ($Expected -cne $Actual) {
        throw "$Case failed. Expected [$Expected], got [$Actual]"
    }
}

function Assert-RoundTrip {
    param([string] $Case, [string] $Initial, [int] $AddCode, [string] $Mode)
    Set-TestValue $Initial
    Assert-Equal $AddCode (Invoke-Helper -Action Add) "$Case add status"
    Assert-Equal 0 (Invoke-Helper -Action Remove -RemoveMode $Mode) "$Case remove status"
    Assert-Equal $Initial (Get-TestValue) "$Case round trip"
}

try {
    Assert-RoundTrip "normal" "alpha;beta" 0 "AddedSeparator"
    Assert-RoundTrip "trailing separator" "alpha;beta;" 11 "TrailingSeparator"
    Assert-RoundTrip "consecutive separators" "alpha;;beta;;;gamma" 0 "AddedSeparator"
    Assert-RoundTrip "whitespace" " alpha ;  beta  " 0 "AddedSeparator"
    Assert-RoundTrip "empty" "" 12 "OnlyEntry"

    $present = "alpha; $entry ;beta"
    Set-TestValue $present
    Assert-Equal 10 (Invoke-Helper -Action Add) "already-present add status"
    Assert-Equal $present (Get-TestValue) "already-present unchanged"

    Set-TestValue "alpha;beta"
    Assert-Equal 0 (Invoke-Helper -Action Add) "unrelated edit add status"
    Set-TestValue "gamma;$(Get-TestValue);delta"
    Assert-Equal 0 (Invoke-Helper -Action Remove -RemoveMode "AddedSeparator") "unrelated edit remove status"
    Assert-Equal "gamma;alpha;beta;delta" (Get-TestValue) "unrelated edits preserved"

    Write-Output "UPDATE_PATH_TESTS_OK=7"
}
finally {
    [Environment]::SetEnvironmentVariable($variable, $null, "User")
}
