#!/usr/bin/env bash
# Install the conmanctl bundled with ConMan.app into the conventional macOS PATH.

set -euo pipefail

# The overrides exist for the packaging contract test. Normal interactive use
# intentionally has one documented location and needs no environment setup.
link_path="${CONMANCTL_INSTALL_LINK:-/usr/local/bin/conmanctl}"
app_path="${CONMANCTL_INSTALL_APP:-/Applications/ConMan.app}"
cli_path="${app_path}/Contents/Helpers/conmanctl"

run_admin() {
    local parent
    parent=$(dirname "$link_path")
    if [[ -d "$parent" && -w "$parent" ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

is_conman_link() {
    [[ -L "$link_path" ]] || return 1
    local destination
    destination=$(readlink "$link_path")
    [[ "$destination" == "$cli_path" ]]
}

if [[ "${1:-}" == "--remove" ]]; then
    if is_conman_link; then
        run_admin rm -f "$link_path"
        echo "Removed $link_path"
    elif [[ -e "$link_path" || -L "$link_path" ]]; then
        echo "Refusing to remove $link_path because it was not installed by ConMan." >&2
        exit 1
    else
        echo "conmanctl is not installed at $link_path"
    fi
    exit 0
fi

if [[ $# -ne 0 ]]; then
    echo "Usage: $(basename "$0") [--remove]" >&2
    exit 2
fi

if [[ ! -x "$cli_path" ]]; then
    cat >&2 <<EOF
ConMan must be installed in /Applications before installing conmanctl.

Drag ConMan.app to Applications, then run this command again.
EOF
    exit 1
fi

if [[ -e "$link_path" || -L "$link_path" ]]; then
    if ! is_conman_link; then
        echo "Refusing to replace an unrelated item at $link_path" >&2
        exit 1
    fi
fi

run_admin mkdir -p "$(dirname "$link_path")"
run_admin ln -sfn "$cli_path" "$link_path"

echo "Installed conmanctl at $link_path"
echo "Run 'conmanctl --version' in a new Terminal window to verify it."
