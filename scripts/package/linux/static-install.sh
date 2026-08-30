#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${PREFIX:-/usr/local}
DATA_PREFIX=${DATA_PREFIX:-/usr/local/share}

if [ "$(id -u)" -ne 0 ] && [ "$PREFIX" = /usr/local ]; then
    PREFIX="${HOME}/.local"
    DATA_PREFIX="${HOME}/.local/share"
fi

install -Dm0755 "${SCRIPT_DIR}/bin/conman" "${PREFIX}/bin/conman"
install -Dm0755 "${SCRIPT_DIR}/bin/conmanctl" "${PREFIX}/bin/conmanctl"
install -Dm0644 "${SCRIPT_DIR}/share/applications/com.marcos0ft.conman.desktop" \
    "${DATA_PREFIX}/applications/com.marcos0ft.conman.desktop"
install -Dm0644 "${SCRIPT_DIR}/share/metainfo/com.marcos0ft.conman.appdata.xml" \
    "${DATA_PREFIX}/metainfo/com.marcos0ft.conman.appdata.xml"
install -Dm0644 "${SCRIPT_DIR}/share/icons/hicolor/128x128/apps/com.marcos0ft.conman.png" \
    "${DATA_PREFIX}/icons/hicolor/128x128/apps/com.marcos0ft.conman.png"
if [ -d "${SCRIPT_DIR}/share/doc/conman" ]; then
    mkdir -p "${DATA_PREFIX}/doc/conman"
    for notice in "${SCRIPT_DIR}"/share/doc/conman/*; do
        install -m0644 "$notice" "${DATA_PREFIX}/doc/conman/$(basename "$notice")"
    done
fi

printf 'Installed conman and conmanctl under %s\n' "$PREFIX"
case ":${PATH}:" in
    *":${PREFIX}/bin:"*) ;;
    *) printf 'Add %s/bin to PATH.\n' "$PREFIX" ;;
esac
