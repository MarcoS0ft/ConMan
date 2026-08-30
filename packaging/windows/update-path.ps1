[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Add", "Remove")]
    [string] $Action,

    [Parameter(Mandatory)]
    [ValidateSet("Process", "User", "Machine")]
    [string] $Scope,

    [Parameter(Mandatory)]
    [string] $Entry,

    [Parameter()]
    [ValidateSet("AddedSeparator", "TrailingSeparator", "OnlyEntry")]
    [string] $RemoveMode,

    [Parameter()]
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string] $VariableName = "Path"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $Entry -or $Entry.Contains(';')) {
    throw "The PATH entry is empty or contains a semicolon"
}

$target = [EnvironmentVariableTarget]::$Scope
$current = [Environment]::GetEnvironmentVariable($VariableName, $target)
if ($null -eq $current) { $current = "" }
$parts = @($current.Split(';'))
$present = [bool]($parts | Where-Object {
    $_.Trim().Equals($Entry, [StringComparison]::OrdinalIgnoreCase)
})

if ($Action -eq "Add") {
    if ($present) { exit 10 }
    if (-not $current) {
        $updated = $Entry
        $result = 12 # OnlyEntry
    } elseif ($current.EndsWith(';')) {
        $updated = "$current$Entry"
        $result = 11 # TrailingSeparator
    } else {
        $updated = "$current;$Entry"
        $result = 0 # AddedSeparator
    }
} else {
    if (-not $RemoveMode) {
        throw "RemoveMode is required when removing an installer-owned PATH entry"
    }
    if (-not $present) { exit 10 }

    # Remove one exact token using the same fragment the installer appended.
    # Do not rebuild the complete PATH: empty components, whitespace, trailing
    # separators, and unrelated edits made after installation must survive.
    $escaped = [Regex]::Escape($Entry)
    $matches = [Regex]::Matches(
        $current,
        "(^|;)($escaped)(?=;|$)",
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $match = @($matches | Where-Object { $_.Groups[2].Value -ceq $Entry }) | Select-Object -First 1
    if (-not $match) {
        throw "The installer-owned PATH entry was changed and cannot be removed safely"
    }

    switch ($RemoveMode) {
        "AddedSeparator" {
            if ($match.Groups[1].Value -ne ';') {
                throw "The installer-owned PATH separator is no longer present"
            }
            $updated = $current.Remove($match.Index, $match.Length)
        }
        "TrailingSeparator" {
            $entryGroup = $match.Groups[2]
            $updated = $current.Remove($entryGroup.Index, $entryGroup.Length)
        }
        "OnlyEntry" {
            if ($current.Equals($Entry, [StringComparison]::OrdinalIgnoreCase)) {
                $updated = ""
            } elseif ($match.Index -eq 0 -and $current[$Entry.Length] -eq ';') {
                $updated = $current.Remove(0, $Entry.Length + 1)
            } elseif ($match.Groups[1].Value -eq ';') {
                $updated = $current.Remove($match.Index, $match.Length)
            } else {
                throw "The installer-owned sole PATH entry cannot be removed safely"
            }
        }
    }
    $result = 0
}

[Environment]::SetEnvironmentVariable($VariableName, $updated, $target)
exit $result
