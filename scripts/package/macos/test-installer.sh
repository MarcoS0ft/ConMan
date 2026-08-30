#!/usr/bin/env bash
# Exercise installer ownership checks without touching the machine's real PATH.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/conman-cli-install.XXXXXX")
trap 'rm -rf "$work"' EXIT

app="$work/Applications/ConMan.app"
link="$work/usr-local-bin/conmanctl"
mkdir -p "$app/Contents/Helpers" "$(dirname "$link")"
printf '#!/bin/sh\nexit 0\n' > "$app/Contents/Helpers/conmanctl"
chmod 0755 "$app/Contents/Helpers/conmanctl"

installer="$repo_root/packaging/macos/Install conmanctl.command"
env CONMANCTL_INSTALL_APP="$app" CONMANCTL_INSTALL_LINK="$link" \
    "$installer" >/dev/null
[[ -L "$link" && $(readlink "$link") == "$app/Contents/Helpers/conmanctl" ]]

env CONMANCTL_INSTALL_APP="$app" CONMANCTL_INSTALL_LINK="$link" \
    "$installer" --remove >/dev/null
[[ ! -e "$link" && ! -L "$link" ]]

printf 'unrelated\n' > "$link"
if env CONMANCTL_INSTALL_APP="$app" CONMANCTL_INSTALL_LINK="$link" \
    "$installer" >/dev/null 2>&1; then
    echo "Installer unexpectedly replaced an unrelated file" >&2
    exit 1
fi
[[ $(cat "$link") == "unrelated" ]]

echo "Validated conmanctl install, removal, and ownership refusal"
