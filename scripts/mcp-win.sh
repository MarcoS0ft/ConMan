#!/usr/bin/env bash
# P8.3 — win11-dev wrapper for the Slint-native MCP automation surface.
#
# Uses the P6.17-proven durable launch shape: a real Scheduled Task plus an
# SSH local-forward — a foreground SSH command or
# `Start-Process` both lose the process on session disconnect, see
# memos/win11-dev-vm-ops.md "ConMan QA runner"), but registers/triggers
# **ConManMCP**, forwards `SLINT_MCP_PORT`, and drives the target over MCP
# (`scripts/mcp-scenario-driver.py`).
#
# The task's action runs a `run-mcp.ps1` deployed directly on the VM (NOT
# tracked in this repo: host-specific infra scripts live only on the box, per the
# P6.2b "no host details in tracked scripts" rule). `run-mcp.ps1` must, at
# minimum:
#   - write a sentinel as its literal first line (before any try/catch) —
#     memos/win11-dev-vm-ops.md's "sentinel-first-line" rule, so a later run
#     can distinguish "never ran" from "still running" from "crashed";
#   - set $env:SLINT_MCP_PORT, $env:SLINT_BACKEND = "software" (this VM has no
#     usable hardware OpenGL — same finding as the ConManQA runner) and
#     optionally $env:CONMAN_DB_PATH / $env:CONMAN_AUTOIMPORT (P8.3's "reuse
#     the existing data-seeding seams" note);
#   - launch a `conman.exe` that was built with `--features automation`.
#
# All host/user/path details are supplied via environment variables — nothing
# machine-specific is hard-coded here (CONVENTIONS: infra notes/host details
# stay in the gitignored runbook, never in tracked files).
#
# Usage:
#   scripts/mcp-win.sh register   # one-time: create/replace the ConManMCP task
#   scripts/mcp-win.sh run        # trigger it, open the tunnel, run the scenario
#   scripts/mcp-win.sh tunnel     # trigger + open the tunnel only, print connect
#                                  # info, and stay in the foreground (Ctrl-C to
#                                  # close) — for an interactive MCP-native agent
#                                  # session instead of the scripted `run` leg.
#
# Required env vars:
#   WIN_SSH_HOST     - ssh destination for the Windows box (ssh config alias
#                       or user@host), with working key auth already set up.
#   WIN_MCP_SCRIPT   - Windows path to run-mcp.ps1 on the box (e.g.
#                       'C:\dev\ConMan\qa\run-mcp.ps1').
#
# Optional env vars (defaults in parentheses):
#   WIN_MCP_PORT       (48900)     - SLINT_MCP_PORT run-mcp.ps1 is expected to use.
#   WIN_MCP_TASK_NAME  (ConManMCP) - Task Scheduler task name.
#   LOCAL_FWD_PORT     (WIN_MCP_PORT) - local port the SSH tunnel forwards to
#                                        WIN_MCP_PORT.
#   OUT_DIR            (mktemp -d) - local dir for the screenshot + transcript.
#   HOST_VALUE         (mark42-mcp-win.lab) - value set into the HOST field by
#                                              the `run` scenario.
#
# Requires on this machine: ssh, python3 (for scripts/mcp-scenario-driver.py).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${WIN_SSH_HOST:?set WIN_SSH_HOST (ssh destination for the Windows box)}"
WIN_MCP_PORT="${WIN_MCP_PORT:-48900}"
WIN_MCP_TASK_NAME="${WIN_MCP_TASK_NAME:-ConManMCP}"
LOCAL_FWD_PORT="${LOCAL_FWD_PORT:-$WIN_MCP_PORT}"
HOST_VALUE="${HOST_VALUE:-mark42-mcp-win.lab}"
OUT_DIR="${OUT_DIR:-}"
[ -z "$OUT_DIR" ] && OUT_DIR="$(mktemp -d)"
mkdir -p "$OUT_DIR"

cmd="${1:-}"

cmd_register() {
    : "${WIN_MCP_SCRIPT:?set WIN_MCP_SCRIPT (Windows path to run-mcp.ps1)}"
    # `/it` (interactive-only) + no explicit `/RU` targets the currently
    # logged-on interactive user — required for winit/the software renderer
    # to attach to a real desktop session at all (see the ConManQA precedent
    # in memos/win11-dev-vm-ops.md).
    echo "mcp-win: registering scheduled task '${WIN_MCP_TASK_NAME}' on ${WIN_SSH_HOST}"
    ssh "$WIN_SSH_HOST" \
        "schtasks /create /tn \"${WIN_MCP_TASK_NAME}\" /tr \"powershell -NoProfile -ExecutionPolicy Bypass -File \\\"${WIN_MCP_SCRIPT}\\\"\" /sc once /st 23:59 /it /f" \
        | grep -vE "Show-Help" || true
    echo "mcp-win: registered. Run 'scripts/mcp-win.sh run' or 'tunnel' to trigger it."
}

open_tunnel_and_wait() {
    echo "mcp-win: triggering '${WIN_MCP_TASK_NAME}' on ${WIN_SSH_HOST}"
    ssh "$WIN_SSH_HOST" "schtasks /run /tn \"${WIN_MCP_TASK_NAME}\"" | grep -vE "Show-Help" || true

    echo "mcp-win: opening SSH port-forward 127.0.0.1:${LOCAL_FWD_PORT} -> ${WIN_SSH_HOST}:${WIN_MCP_PORT}"
    # -4 forces IPv4: a dual-stack `ssh -N -L` here failed outright with
    # "bind [::1]:<port>: Cannot assign requested address" on a host where
    # IPv6 loopback bind is unavailable — observed directly in this task's
    # win11-dev verification pass; forcing IPv4 avoids it.
    ssh -4 -N -L "${LOCAL_FWD_PORT}:127.0.0.1:${WIN_MCP_PORT}" "$WIN_SSH_HOST" &
    TUNNEL_PID=$!

    # Bounded poll for the scheduled task to have actually started conman.exe
    # and bound the MCP loopback port (interactive-desktop startup is not
    # instant).
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
        echo "mcp-win: MCP port never came up through the tunnel — confirm a user is" >&2
        echo "  logged on to the Windows console session and run-mcp.ps1's log for errors." >&2
        kill "$TUNNEL_PID" 2>/dev/null || true
        exit 1
    fi
}

cmd_run() {
    open_tunnel_and_wait
    cleanup() { kill "$TUNNEL_PID" 2>/dev/null || true; wait "$TUNNEL_PID" 2>/dev/null || true; }
    trap cleanup EXIT

    status=0
    python3 "$REPO_ROOT/scripts/mcp-scenario-driver.py" \
        --port "$LOCAL_FWD_PORT" \
        --out-dir "$OUT_DIR" \
        --transcript "$OUT_DIR/mcp-win-transcript.txt" \
        --host-value "$HOST_VALUE" \
        --screenshot-name "mcp-win.png" || status=$?

    if [ "$status" -ne 0 ]; then
        echo "mcp-win: scenario FAILED against ${WIN_SSH_HOST}" >&2
        exit "$status"
    fi
    echo "mcp-win: PASS — screenshot + transcript in ${OUT_DIR}"
}

cmd_tunnel() {
    open_tunnel_and_wait
    cat <<EOF
mcp-win: tunnel ready — MCP server reachable at http://127.0.0.1:${LOCAL_FWD_PORT}/mcp

.mcp.json stanza (MCP-native agents):
{
  "mcpServers": {
    "conman-win11-dev": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:${LOCAL_FWD_PORT}/mcp"
    }
  }
}

Ctrl-C to close the tunnel.
EOF
    cleanup() { kill "$TUNNEL_PID" 2>/dev/null || true; wait "$TUNNEL_PID" 2>/dev/null || true; }
    trap cleanup EXIT INT TERM
    wait "$TUNNEL_PID"
}

case "$cmd" in
    register) cmd_register ;;
    run) cmd_run ;;
    tunnel) cmd_tunnel ;;
    *)
        echo "usage: $0 {register|run|tunnel}" >&2
        exit 2
        ;;
esac
