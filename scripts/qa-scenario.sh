#!/usr/bin/env bash
# P6.2b Part A — sample QA-harness driver scenario.
#
# Launches a `qa-harness`-enabled `conman` build, waits for the loopback QA
# socket to come up, drives it through the JSON-lines protocol (state dump,
# type a probe command into the default local tab, screenshot), and quits.
# Exercises the exact same protocol Part B's Windows runner drives remotely
# over an SSH port-forward — see docs/devel/tasks/P6.2b-remote-qa-harness.md.
#
# Usage:
#   scripts/qa-scenario.sh [--binary PATH] [--out-dir DIR] [--port N] [--dark|--light]
#
# Env overrides (all optional):
#   CONMAN_BIN        - path to the conman binary (default: search CARGO_TARGET_DIR
#                        then ./target for debug/release conman)
#   QA_SCENARIO_PORT   - loopback port for the QA socket (default: 47811)
#   QA_SCENARIO_OUT    - directory to write screenshot PNGs into (default: mktemp -d)
#   SLINT_BACKEND       - forwarded to conman; defaults to winit-femtovg (the backend
#                          confirmed to support take_snapshot() under xvfb)
#
# Requires: xvfb-run (or an already-available DISPLAY), python3.
#
# Exit code: 0 on a fully passing scenario; non-zero and a message on the first
# failing step (never silently continues past a failed assertion).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BINARY="${CONMAN_BIN:-}"
PORT="${QA_SCENARIO_PORT:-47811}"
OUT_DIR="${QA_SCENARIO_OUT:-}"
THEME="dark"

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --dark) THEME="dark"; shift ;;
        --light) THEME="light"; shift ;;
        *) echo "qa-scenario: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$BINARY" ]; then
    for cand in \
        "${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/conman" \
        "${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/conman"
    do
        if [ -x "$cand" ]; then BINARY="$cand"; break; fi
    done
fi
if [ -z "$BINARY" ] || [ ! -x "$BINARY" ]; then
    echo "qa-scenario: no conman binary found (build with --features qa-harness and pass --binary, or set CONMAN_BIN)" >&2
    exit 2
fi

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$(mktemp -d)"
fi
mkdir -p "$OUT_DIR"

DARK_FLAG=1
[ "$THEME" = "light" ] && DARK_FLAG=0

echo "qa-scenario: binary=$BINARY port=$PORT theme=$THEME out_dir=$OUT_DIR"

launch_wrapper() {
    if [ -n "${DISPLAY:-}" ]; then
        # Already have a display (e.g. real Windows desktop via Part B, or a
        # dev machine) — run directly, no Xvfb needed.
        "$@"
    else
        xvfb-run -a "$@"
    fi
}

CONMAN_QA_PORT="$PORT" \
    CONMAN_DARK_MODE="$DARK_FLAG" \
    SLINT_BACKEND="${SLINT_BACKEND:-winit-femtovg}" \
    launch_wrapper "$BINARY" &
APP_PID=$!

cleanup() {
    # When wrapped in xvfb-run, $APP_PID is the xvfb-run shell, not conman
    # itself. If xvfb-run's own shell is killed (or dies from `timeout`)
    # before it forwards the signal, conman is reparented to init and keeps
    # running as an orphan holding the single-instance loopback lock
    # (cm-platform, port 52734) — which then blocks the *next* scenario run
    # from ever starting. Match by the exact binary path (not just "conman",
    # and not Xvfb — this host runs several agents' builds in parallel, so
    # only kill what *this* script launched) rather than relying on process
    # tree parentage, which is not reliable across xvfb-run/timeout layers.
    pkill -TERM -f "$BINARY" 2>/dev/null || true
    if kill -0 "$APP_PID" 2>/dev/null; then
        kill "$APP_PID" 2>/dev/null || true
        wait "$APP_PID" 2>/dev/null || true
    fi
    sleep 0.2
    pkill -KILL -f "$BINARY" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for the QA socket to accept connections (bounded poll, no fixed sleep
# for command sequencing — only for the one-time process-startup race). 30s
# covers a loaded/shared build host (winit + software GL under xvfb can take
# a few seconds to come up even when the host is otherwise idle).
ready=0
for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        exec 3>&- 3<&-
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "qa-scenario: QA socket on 127.0.0.1:$PORT never came up" >&2
    exit 1
fi

status=0
python3 "$REPO_ROOT/scripts/qa-scenario-driver.py" \
    --port "$PORT" \
    --out-dir "$OUT_DIR" \
    --theme "$THEME" || status=$?

if [ "$status" -eq 0 ]; then
    echo "qa-scenario: PASS ($THEME) — screenshot(s) in $OUT_DIR"
else
    echo "qa-scenario: FAIL ($THEME)" >&2
fi
exit "$status"
