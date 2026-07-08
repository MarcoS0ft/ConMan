#!/usr/bin/env bash
# P7.4 — repeatable visual-QA gate runner.
#
# Launches a `qa-harness`-enabled `conman` build once per theme (light, dark),
# waits for the loopback QA socket, and runs `qa-visual-suite.py` (the full
# rubric check suite — see docs/devel/memos/P7.4-visual-qa-rubric.md) against
# each. Mirrors scripts/qa-scenario.sh's launch/cleanup pattern so it runs
# identically under Linux xvfb and on a real Windows/Linux desktop (Part B's
# win11-dev runner: no Xvfb needed there, same script).
#
# Usage:
#   scripts/qa-visual-suite.sh [--binary PATH] [--out-dir DIR] [--port N]
#                              [--dark-only|--light-only]
#
# Env overrides (all optional):
#   CONMAN_BIN            - path to the conman binary (default: search
#                            CARGO_TARGET_DIR then ./target for debug/release conman)
#   QA_SUITE_PORT          - base loopback port for the QA socket (default: 47920;
#                             the dark run uses PORT+1 so both legs' cleanup traps
#                             never race each other if run back-to-back)
#   QA_SUITE_INSTANCE_PORT - base port for ConMan's single-instance loopback lock
#                            (default: 58920; +1 for the dark run) — MUST differ
#                            from other agents'/scripts' concurrent conman
#                            instances on a shared build host, or this run's
#                            launch silently activates someone else's window
#                            instead of starting its own (cm_platform::
#                            single_instance; see CONMAN_INSTANCE_PORT).
#   QA_SUITE_OUT           - directory to write screenshots + JSON reports into
#                            (default: mktemp -d)
#   SLINT_BACKEND          - forwarded to conman; defaults to winit-femtovg
#   QA_RDP_HOST/QA_RDP_USER/QA_RDP_PASSWORD - optional live-RDP smoke target;
#                            the check SKIPs (not FAILs) if unset.
#
# Requires: xvfb-run (unless $DISPLAY is already set), python3.
#
# Exit code: 0 if every requested theme's suite RAN to completion (no
# harness/protocol-level ERROR); non-zero otherwise. Individual rubric
# checks PASSing or FAILing is reported in the output/JSON, not reflected in
# the exit code — this suite is expected to fail several checks against a
# not-yet-fixed master by design (see the rubric memo).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BINARY="${CONMAN_BIN:-}"
BASE_PORT="${QA_SUITE_PORT:-47920}"
BASE_INSTANCE_PORT="${QA_SUITE_INSTANCE_PORT:-58920}"
OUT_DIR="${QA_SUITE_OUT:-}"
THEMES="light dark"

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --port) BASE_PORT="$2"; shift 2 ;;
        --light-only) THEMES="light"; shift ;;
        --dark-only) THEMES="dark"; shift ;;
        *) echo "qa-visual-suite: unknown argument: $1" >&2; exit 2 ;;
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
    echo "qa-visual-suite: no conman binary found (build with --features cm-ui/qa-harness and pass --binary, or set CONMAN_BIN)" >&2
    exit 2
fi

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$(mktemp -d)"
fi
mkdir -p "$OUT_DIR"

echo "qa-visual-suite: binary=$BINARY out_dir=$OUT_DIR themes=[$THEMES]"

launch_wrapper() {
    if [ -n "${DISPLAY:-}" ]; then
        "$@"
    else
        xvfb-run -a -s "-screen 0 1400x900x24" "$@"
    fi
}

run_one_theme() {
    theme="$1"
    port="$2"
    instance_port="$3"
    dark_flag=1
    [ "$theme" = "light" ] && dark_flag=0

    echo "--- qa-visual-suite: launching conman ($theme) on port $port (instance lock $instance_port) ---"
    CONMAN_QA_PORT="$port" \
        CONMAN_INSTANCE_PORT="$instance_port" \
        CONMAN_DARK_MODE="$dark_flag" \
        SLINT_BACKEND="${SLINT_BACKEND:-winit-femtovg}" \
        launch_wrapper "$BINARY" &
    app_pid=$!

    cleanup_one() {
        # Same rationale as qa-scenario.sh's cleanup: match by exact binary
        # path (this host runs several agents' worktree builds in parallel,
        # each under its own CARGO_TARGET_DIR, so the path itself already
        # disambiguates them) rather than relying on process-tree
        # parentage, which is not reliable across xvfb-run layers. The two
        # themes in this script's own loop run sequentially (never
        # concurrently), so there is no need to further scope by
        # instance_port here.
        pkill -TERM -f "$BINARY" 2>/dev/null || true
        if kill -0 "$app_pid" 2>/dev/null; then
            kill "$app_pid" 2>/dev/null || true
            wait "$app_pid" 2>/dev/null || true
        fi
        sleep 0.2
        pkill -KILL -f "$BINARY" 2>/dev/null || true
    }
    trap cleanup_one RETURN

    ready=0
    for _ in $(seq 1 300); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&- 3<&-
            ready=1
            break
        fi
        sleep 0.1
    done
    if [ "$ready" -ne 1 ]; then
        echo "qa-visual-suite: QA socket on 127.0.0.1:$port never came up ($theme)" >&2
        return 1
    fi

    python3 "$REPO_ROOT/scripts/qa-visual-suite.py" \
        --port "$port" \
        --theme "$theme" \
        --out-dir "$OUT_DIR" \
        --json-out "$OUT_DIR/report-$theme.json"
}

overall=0
i=0
for theme in $THEMES; do
    port=$((BASE_PORT + i))
    instance_port=$((BASE_INSTANCE_PORT + i))
    if ! run_one_theme "$theme" "$port" "$instance_port"; then
        overall=1
    fi
    i=$((i + 1))
done

echo
echo "qa-visual-suite: reports in $OUT_DIR/report-{light,dark}.json; screenshots alongside them."
exit "$overall"
