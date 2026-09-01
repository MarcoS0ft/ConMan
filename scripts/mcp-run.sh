#!/usr/bin/env bash
# Linux launcher for the Slint-native MCP automation surface.
#
# Builds (if needed) and launches a `conman` binary built with
# `--features automation` (= `slint/mcp` + `cm-ui/ui-introspection`, both off
# by default), with
# `SLINT_MCP_PORT` set so the embedded MCP server starts
# (`i-slint-backend-testing`'s `mcp_server.rs`; no port set = no server, zero
# overhead — this script is the only thing that ever sets that env var).
#
# Runs the app **in the background** (detached, like a daemon) so the calling
# shell/agent gets control back once the MCP endpoint is ready to accept
# connections — the whole point is to then drive it over MCP from a separate
# tool call/process. State (PID, log path, port) is tracked in a small run
# directory so a later `stop`/`status` invocation can find it again.
#
# Usage:
#   scripts/mcp-run.sh start  [--build] [--binary PATH] [--port N]
#                              [--mode xvfb|headless] [--db-path PATH]
#                              [--autoimport PATH] [--run-dir DIR]
#   scripts/mcp-run.sh status [--run-dir DIR]
#   scripts/mcp-run.sh stop   [--run-dir DIR]
#
# Env overrides (all optional, same defaults as the flags above):
#   CONMAN_BIN, MCP_RUN_PORT (48900), MCP_RUN_MODE (xvfb), MCP_RUN_DIR
#   (mktemp -d on first `start`, then reused), CONMAN_DB_PATH, CONMAN_AUTOIMPORT
#   (forwarded to the application's existing data-seeding interfaces).
#
# `--mode xvfb` (default): launches under `xvfb-run` with
# `SLINT_BACKEND=winit-femtovg` — the real GPU-path renderer, confirmed to
# support every MCP tool including `take_screenshot` under Xvfb.
# `--mode headless`: no Xvfb, `SLINT_BACKEND=headless` (the
# windowless software rasterizer the `mcp` feature unlocks) — also confirmed
# to support the full tool set including screenshots; use
# this on a box with no X server at all (e.g. a minimal CI container).
#
# On `start`, once the port is confirmed open, prints:
#   - the `.mcp.json` stanza for MCP-native agents
#   - a ready-to-run `curl` `initialize` snippet for scripts
#   - the PID + run dir, and how to `stop` it
#
# Requires: xvfb-run (for --mode xvfb), cargo (if --build or no binary found).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PORT="${MCP_RUN_PORT:-48900}"
MODE="${MCP_RUN_MODE:-xvfb}"
RUN_DIR="${MCP_RUN_DIR:-}"
BINARY="${CONMAN_BIN:-}"
DO_BUILD=0

cmd="${1:-}"
[ $# -gt 0 ] && shift || true

while [ $# -gt 0 ]; do
    case "$1" in
        --build) DO_BUILD=1; shift ;;
        --binary) BINARY="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --db-path) CONMAN_DB_PATH="$2"; shift 2 ;;
        --autoimport) CONMAN_AUTOIMPORT="$2"; shift 2 ;;
        --run-dir) RUN_DIR="$2"; shift 2 ;;
        *) echo "mcp-run: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$RUN_DIR" ]; then
    # Stable default so `status`/`stop` find the same dir as a preceding
    # `start` without the caller having to pass --run-dir every time.
    RUN_DIR="${TMPDIR:-/tmp}/conman-mcp-run"
fi
mkdir -p "$RUN_DIR"
PID_FILE="$RUN_DIR/conman.pid"
XVFB_PID_FILE="$RUN_DIR/xvfb.pid"
LOG_FILE="$RUN_DIR/conman.log"
PORT_FILE="$RUN_DIR/port"
BINARY_FILE="$RUN_DIR/binary-path"

wait_for_port() {
    local port="$1" tries="${2:-300}"
    for _ in $(seq 1 "$tries"); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&- 3<&-
            return 0
        fi
        sleep 0.1
    done
    return 1
}

print_connect_info() {
    local port="$1"
    cat <<EOF
mcp-run: MCP server ready at http://127.0.0.1:${port}/mcp

.mcp.json stanza (MCP-native agents):
{
  "mcpServers": {
    "conman": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:${port}/mcp"
    }
  }
}

curl initialize (scripts):
curl -s -X POST http://127.0.0.1:${port}/mcp -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cli","version":"1.0"}}}'

Driver: scripts/mcp-scenario-driver.py --port ${port} --out-dir <dir>
Stop:   scripts/mcp-run.sh stop --run-dir ${RUN_DIR}
EOF
}

cmd_start() {
    if [ -z "$BINARY" ]; then
        for cand in \
            "${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/conman" \
            "${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/conman"
        do
            if [ -x "$cand" ]; then BINARY="$cand"; break; fi
        done
    fi
    if [ "$DO_BUILD" -eq 1 ] || [ -z "$BINARY" ] || [ ! -x "$BINARY" ]; then
        echo "mcp-run: building conman --features automation (this can take a while the first time)"
        (cd "$REPO_ROOT" && cargo build -p conman --features automation)
        BINARY="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/conman"
    fi
    if [ ! -x "$BINARY" ]; then
        echo "mcp-run: no conman binary at '$BINARY' (build with --features automation, or pass --binary/--build)" >&2
        exit 2
    fi

    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "mcp-run: already running (pid $(cat "$PID_FILE")); 'stop' first or use a different --run-dir" >&2
        exit 1
    fi

    echo "mcp-run: binary=$BINARY port=$PORT mode=$MODE run_dir=$RUN_DIR"
    echo "$BINARY" > "$BINARY_FILE"
    echo "$PORT" > "$PORT_FILE"
    : > "$LOG_FILE"

    case "$MODE" in
        xvfb)
            setsid xvfb-run -a env \
                SLINT_MCP_PORT="$PORT" \
                SLINT_BACKEND="${SLINT_BACKEND:-winit-femtovg}" \
                ${CONMAN_DB_PATH:+CONMAN_DB_PATH="$CONMAN_DB_PATH"} \
                ${CONMAN_AUTOIMPORT:+CONMAN_AUTOIMPORT="$CONMAN_AUTOIMPORT"} \
                "$BINARY" >"$LOG_FILE" 2>&1 &
            echo $! > "$XVFB_PID_FILE"
            ;;
        headless)
            setsid env \
                SLINT_MCP_PORT="$PORT" \
                SLINT_BACKEND="${SLINT_BACKEND:-headless}" \
                ${CONMAN_DB_PATH:+CONMAN_DB_PATH="$CONMAN_DB_PATH"} \
                ${CONMAN_AUTOIMPORT:+CONMAN_AUTOIMPORT="$CONMAN_AUTOIMPORT"} \
                "$BINARY" >"$LOG_FILE" 2>&1 &
            ;;
        *)
            echo "mcp-run: unknown --mode '$MODE' (want xvfb|headless)" >&2
            exit 2
            ;;
    esac
    local launcher_pid=$!

    # The actual `conman` PID may differ from $launcher_pid under xvfb-run
    # (which forks a wrapper shell) — find it by matching the exact binary
    # path.
    local conman_pid=""
    for _ in $(seq 1 100); do
        conman_pid="$(pgrep -f -x "$BINARY" 2>/dev/null | head -1 || true)"
        [ -n "$conman_pid" ] && break
        sleep 0.1
    done
    if [ -z "$conman_pid" ]; then
        conman_pid="$launcher_pid"
    fi
    echo "$conman_pid" > "$PID_FILE"

    if ! wait_for_port "$PORT"; then
        echo "mcp-run: MCP server on 127.0.0.1:$PORT never came up — see $LOG_FILE" >&2
        cat "$LOG_FILE" >&2 || true
        exit 1
    fi
    print_connect_info "$PORT"
}

cmd_status() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        local port; port="$(cat "$PORT_FILE" 2>/dev/null || echo '?')"
        echo "mcp-run: running (pid $(cat "$PID_FILE"), port $port, run_dir $RUN_DIR)"
        exit 0
    fi
    echo "mcp-run: not running (run_dir $RUN_DIR)"
    exit 1
}

cmd_stop() {
    local binary; binary="$(cat "$BINARY_FILE" 2>/dev/null || echo '')"
    if [ -n "$binary" ]; then
        pkill -TERM -f -x "$binary" 2>/dev/null || true
    elif [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
    fi
    if [ -f "$XVFB_PID_FILE" ]; then
        kill "$(cat "$XVFB_PID_FILE")" 2>/dev/null || true
    fi
    sleep 0.3
    [ -n "$binary" ] && pkill -KILL -f -x "$binary" 2>/dev/null || true
    rm -f "$PID_FILE" "$XVFB_PID_FILE" "$PORT_FILE"
    echo "mcp-run: stopped"
}

case "$cmd" in
    start) cmd_start ;;
    status) cmd_status ;;
    stop) cmd_stop ;;
    *)
        echo "usage: $0 {start|status|stop} [options]" >&2
        exit 2
        ;;
esac
