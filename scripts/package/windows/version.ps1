# Windows Installer compares only major.minor.build (limits 255.255.65535).
# Keep SemVer major/minor and use Git chronology for patch/dev ordering.
function Get-ConManMsiVersion {
    param(
        [Parameter(Mandatory)] [string] $Version,
        [Parameter(Mandatory)] [long] $Revision
    )

    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-dev\.([1-9][0-9]*)\+g[0-9a-f]{10}(?:\.dirty)?)?$') {
        throw "MSI requires a stable or Git-derived ConMan version, got '$Version'"
    }
    $major = [long]$Matches[1]
    $minor = [long]$Matches[2]
    $devRevision = $Matches[4]
    if ($major -gt 255 -or $minor -gt 255 -or $Revision -lt 1 -or $Revision -gt 32767) {
        throw "MSI version exceeds its numeric limits (major/minor <= 255, Git revision 1..32767)"
    }
    $stable = 1
    if ($devRevision) {
        if ([long]$devRevision -ne $Revision) {
            throw "Binary development revision $devRevision does not match checkout revision $Revision"
        }
        $stable = 0
    }
    return "$major.$minor.$(2 * $Revision + $stable)"
}
