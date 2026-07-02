#!/usr/bin/env bash
# P6.2b Part B — Windows QA runner (infra script; no host details tracked).
#
# STATUS: UNVERIFIED end-to-end. This script codifies the steps in
# docs/devel/tasks/P6.2b-remote-qa-harness.md Part B against the patterns in the
# gitignored docs/devel/memos/windows-build-ops.md runbook, but it has not been
# exercised against a real Windows box in this environment: Part B's one-time
# human-assisted autologon setup (spec step 1) has not been performed, and this
# environment has no SSH access to the Windows test box. Treat this as reviewed
# scaffolding, not a proven runbook — the first real run should be watched
# closely and this file's comments updated with whatever it gets wrong.
#
# All host/user/path details are supplied via environment variables — nothing
# machine-specific is hard-coded here (CONVENTIONS: infra notes/host details stay
# in the gitignored runbook, never in tracked files).
#
# Usage:
#   scripts/qa-win.sh register   # one-time: create/replace the ConManQA scheduled task
#   scripts/qa-win.sh run        # trigger it, drive the QA socket, retrieve screenshots
#
# Required env vars:
#   WIN_SSH_HOST      - ssh destination for the Windows box (e.g. an ssh config alias,
#                        or user@host). Must already have working key auth (see runbook).
#   WIN_QA_EXE        - path to the qa-harness-enabled conman.exe on the Windows box
#                        (Windows path, e.g. 'C:\Users\...\target\debug\conman.exe').
#
# Optional env vars (defaults in parentheses):
#   WIN_QA_PORT        (47811)   - CONMAN_QA_PORT the scheduled task sets before launch.
#   WIN_QA_TASK_NAME    (ConManQA) - Task Scheduler task name (pinned by the spec).
#   LOCAL_FWD_PORT      (WIN_QA_PORT) - local port the SSH tunnel forwards to WIN_QA_PORT.
#   LINUX_PUSH_HOST      - this machine's SSH-reachable name/IP, used ONLY for the
#                           reverse-scp screenshot retrieval (runbook Gotcha 3: Windows
#                           must be the scp *client*; a Linux->Windows scp corrupts over
#                           the profile-banner-polluted stream). Required for `run`.
#   LINUX_PUSH_USER      (current $USER) - SSH user on this machine for the reverse push.
#   WIN_STAGE_DIR         (same dir as WIN_QA_EXE) - Windows dir to write the screenshot
#                           PNG into before it is pushed back here.
#   OUT_DIR               (mktemp -d) - local directory the retrieved PNGs land in.
#   THEME                 (dark) - dark|light, forwarded to CONMAN_DARK_MODE.
#
# Requires on this machine: ssh, python3 (for scripts/qa-scenario-driver.py).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${WIN_SSH_HOST:?set WIN_SSH_HOST (ssh destination for the Windows box)}"
WIN_QA_PORT="${WIN_QA_PORT:-47811}"
WIN_QA_TASK_NAME="${WIN_QA_TASK_NAME:-ConManQA}"
LOCAL_FWD_PORT="${LOCAL_FWD_PORT:-$WIN_QA_PORT}"
LINUX_PUSH_USER="${LINUX_PUSH_USER:-$USER}"
THEME="${THEME:-dark}"
OUT_DIR="${OUT_DIR:-}"
[ -z "$OUT_DIR" ] && OUT_DIR="$(mktemp -d)"
mkdir -p "$OUT_DIR"

cmd="${1:-}"

cmd_register() {
    : "${WIN_QA_EXE:?set WIN_QA_EXE (Windows path to the qa-harness conman.exe)}"
    # `cmd /c "set VAR=... && "exe""` gives the scheduled task's action a way to set
    # CONMAN_QA_PORT before launch without a separate wrapper script on the Windows
    # side. "Run only when user is logged on" + no /RU (defaults to the interactive
    # user) is what the spec's step 2 asks for — an *interactive* desktop session is
    # required for winit to start at all (see the runbook's "GUI over SSH hangs" note).
    local action="cmd /c \"set CONMAN_QA_PORT=${WIN_QA_PORT} && \\\"${WIN_QA_EXE}\\\"\""
    echo "qa-win: registering scheduled task '${WIN_QA_TASK_NAME}' on ${WIN_SSH_HOST}"
    ssh "$WIN_SSH_HOST" \
        "schtasks /create /tn \"${WIN_QA_TASK_NAME}\" /tr \"${action}\" /sc onlogon /it /f" \
        | grep -vE "Show-Help" || true
    echo "qa-win: registered. Run 'scripts/qa-win.sh run' to trigger it."
}

cmd_run() {
    : "${LINUX_PUSH_HOST:?set LINUX_PUSH_HOST, this machine SSH-reachable name, for the reverse-scp pull}"
    local win_stage_dir="${WIN_STAGE_DIR:-}"
    if [ -z "$win_stage_dir" ]; then
        echo "qa-win: WIN_STAGE_DIR not set and no default is safe to guess (needs a" >&2
        echo "  writable Windows directory) — set it explicitly, e.g. the same dir as" >&2
        echo "  WIN_QA_EXE." >&2
        exit 2
    fi
    local remote_shot_name="qa-scenario-${THEME}.png"
    local remote_shot_path="${win_stage_dir}\\${remote_shot_name}"

    echo "qa-win: triggering '${WIN_QA_TASK_NAME}' on ${WIN_SSH_HOST}"
    ssh "$WIN_SSH_HOST" "schtasks /run /tn \"${WIN_QA_TASK_NAME}\"" | grep -vE "Show-Help" || true

    echo "qa-win: opening SSH port-forward 127.0.0.1:${LOCAL_FWD_PORT} -> ${WIN_SSH_HOST}:${WIN_QA_PORT}"
    ssh -N -L "${LOCAL_FWD_PORT}:127.0.0.1:${WIN_QA_PORT}" "$WIN_SSH_HOST" &
    TUNNEL_PID=$!
    cleanup() {
        kill "$TUNNEL_PID" 2>/dev/null || true
        wait "$TUNNEL_PID" 2>/dev/null || true
    }
    trap cleanup EXIT

    # Bounded poll for the scheduled task to have actually started conman.exe and
    # bound the QA socket (interactive-desktop startup is not instant).
    ready=0
    for _ in $(seq 1 150); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$LOCAL_FWD_PORT") 2>/dev/null; then
            exec 3>&- 3<&-
            ready=1
            break
        fi
        sleep 0.2
    done
    if [ "$ready" -ne 1 ]; then
        echo "qa-win: QA socket never came up through the tunnel — see the runbook's" >&2
        echo "  'GUI over SSH does not attach to the interactive desktop' note; confirm" >&2
        echo "  a user is logged on to the Windows console session." >&2
        exit 1
    fi

    status=0
    python3 "$REPO_ROOT/scripts/qa-scenario-driver.py" \
        --port "$LOCAL_FWD_PORT" \
        --out-dir "$OUT_DIR" \
        --theme "$THEME" \
        --shot-path "$remote_shot_path" || status=$?

    if [ "$status" -ne 0 ]; then
        echo "qa-win: scenario FAILED against ${WIN_SSH_HOST}" >&2
        exit "$status"
    fi

    # Retrieve the PNG: Windows must be the scp *client* (runbook Gotcha 1/3 — a
    # Linux-initiated scp INTO Windows-as-server corrupts on the profile banner), so
    # we ask the Windows box, over our existing ssh session, to push the file back to
    # us. Requires Windows -> here SSH key auth already set up (already true per the
    # runbook's "artifacts/logs -> here" pattern).
    echo "qa-win: retrieving ${remote_shot_path} via Windows-initiated scp push"
    ssh "$WIN_SSH_HOST" \
        "scp -o BatchMode=yes \"${remote_shot_path}\" ${LINUX_PUSH_USER}@${LINUX_PUSH_HOST}:${OUT_DIR}/" \
        | grep -vE "Show-Help" || true

    if [ -f "${OUT_DIR}/${remote_shot_name}" ]; then
        echo "qa-win: PASS — screenshot retrieved at ${OUT_DIR}/${remote_shot_name}"
    else
        echo "qa-win: screenshot push did not land at ${OUT_DIR}/${remote_shot_name}" >&2
        exit 1
    fi
}

case "$cmd" in
    register) cmd_register ;;
    run) cmd_run ;;
    *)
        echo "usage: $0 {register|run}" >&2
        exit 2
        ;;
esac
