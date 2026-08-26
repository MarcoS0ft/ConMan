#!/usr/bin/env bash
# P8.4 -- the unified QA-gate driver: runs (a) the in-process element-test
# suites, (b) the MCP real-binary journey script, (c) the thin visual layer,
# and emits one combined pass/fail/UNVERIFIED report with evidence paths --
# the same functional-hard-gate / visual-advisory split P6.17 pinned.
#
# Runnable on Linux (xvfb or headless, per the P8.3 spike) and win11-dev (the
# ConManMCP task + SSH-forward recipe, scripts/mcp-win.sh). This script does
# NOT itself SSH to win11-dev -- run scripts/mcp-win.sh separately (see
# memos/win11-dev-vm-ops.md) and point --mcp-port at the local end of that
# tunnel with --skip-linux-launch.
#
# Usage (Linux, everything in one go):
#   scripts/qa-gate.sh --out-dir /tmp/qa-gate-out \
#     --ssh-host 127.0.0.1 --ssh-user <ssh-user> --ssh-key-path <ssh-key> \
#     --seed /path/to/seed.json --tree-ssh-label p84-tree-ssh \
#     --tree-rdp-label p84-tree-rdp \
#     --rdp-target-ssh-host <rdp-target-ip> --rdp-target-ssh-user <rdp-target-user>
#
# Usage (win11-dev, MCP+visual legs only, tunnel already open via mcp-win.sh):
#   scripts/qa-gate.sh --out-dir /tmp/qa-gate-win --skip-in-process \
#     --skip-linux-launch --mcp-port 48950 --light \
#     --tree-ssh-label wintgt-ssh --tree-rdp-label wintgt-rdp \
#     --rdp-target-ssh-host <rdp-target-ip> --rdp-target-ssh-user <rdp-target-user>
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT_DIR=""
SKIP_IN_PROCESS=0
SKIP_LINUX_LAUNCH=0
SKIP_MCP=0
SKIP_VISUAL=0
MCP_PORT="${MCP_RUN_PORT:-48930}"
THEME_FLAG="--dark"
SEED_JSON=""
SSH_HOST="" SSH_USER="" SSH_KEY_PATH=""
TREE_SSH_LABEL="" TREE_RDP_LABEL=""
RDP_TARGET_SSH_HOST="" RDP_TARGET_SSH_USER=""
KEYCTL_SESSION_NAME="p84qagate"

while [ $# -gt 0 ]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --skip-in-process) SKIP_IN_PROCESS=1; shift ;;
        --skip-linux-launch) SKIP_LINUX_LAUNCH=1; shift ;;
        --skip-mcp) SKIP_MCP=1; shift ;;
        --skip-visual) SKIP_VISUAL=1; shift ;;
        --mcp-port) MCP_PORT="$2"; shift 2 ;;
        --dark) THEME_FLAG="--dark"; shift ;;
        --light) THEME_FLAG="--light"; shift ;;
        --seed) SEED_JSON="$2"; shift 2 ;;
        --ssh-host) SSH_HOST="$2"; shift 2 ;;
        --ssh-user) SSH_USER="$2"; shift 2 ;;
        --ssh-key-path) SSH_KEY_PATH="$2"; shift 2 ;;
        --tree-ssh-label) TREE_SSH_LABEL="$2"; shift 2 ;;
        --tree-rdp-label) TREE_RDP_LABEL="$2"; shift 2 ;;
        --rdp-target-ssh-host) RDP_TARGET_SSH_HOST="$2"; shift 2 ;;
        --rdp-target-ssh-user) RDP_TARGET_SSH_USER="$2"; shift 2 ;;
        *) echo "qa-gate: unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -z "$OUT_DIR" ] && { echo "qa-gate: --out-dir is required" >&2; exit 2; }
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/SUMMARY.md"
: > "$SUMMARY"

section() { echo -e "\n## $1\n" | tee -a "$SUMMARY"; }
line() { echo "$1" | tee -a "$SUMMARY"; }

echo "# P8.4 QA gate run -- $(date -u +%FT%TZ)" >> "$SUMMARY"

# ---------------------------------------------------------------------------
# (a) In-process element-test suites
# ---------------------------------------------------------------------------
section "(a) In-process element-test suites"
if [ "$SKIP_IN_PROCESS" -eq 1 ]; then
    line "SKIPPED (--skip-in-process)"
else
    (cd "$REPO_ROOT" && cargo test -p cm-ui --features ui-introspection 2>&1 | tee "$OUT_DIR/in-process.log") \
        && line "PASS -- see $OUT_DIR/in-process.log" \
        || line "FAIL -- see $OUT_DIR/in-process.log"
fi

# ---------------------------------------------------------------------------
# (b) MCP real-binary journey script
# ---------------------------------------------------------------------------
section "(b) MCP journey script (functional -- hard gate)"
if [ "$SKIP_MCP" -eq 1 ]; then
    line "SKIPPED (--skip-mcp)"
else
    if [ "$SKIP_LINUX_LAUNCH" -eq 0 ]; then
        BINARY="${CONMAN_BIN:-${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/conman}"
        if [ ! -x "$BINARY" ]; then
            echo "qa-gate: building conman --features automation (no binary at $BINARY)"
            (cd "$REPO_ROOT" && cargo build -p conman --features automation)
        fi
        DB_PATH="$OUT_DIR/mcp-db.sqlite"; rm -f "$DB_PATH"
        LOG_FILE="$OUT_DIR/mcp-launch.log"; : > "$LOG_FILE"
        # A credentialed tree-launch needs a real session keyring (P6.17's
        # finding, reconfirmed live during this task: under a bare xvfb
        # session with no keyctl session, `cm-secrets`'s keyutils backend
        # gets "No matching entry found in secure storage" on every resolve).
        # This launches xvfb+conman DIRECTLY (not through mcp-run.sh) --
        # nesting `keyctl session ... bash -c 'scripts/mcp-run.sh start ...'`
        # (which itself backgrounds a further child) was observed live to
        # kill the grandchild the moment the wrapped `mcp-run.sh` shell
        # returned; the flat, single-level `nohup setsid keyctl session ...
        # & disown` form below is the pattern proven to survive across tool
        # calls during this task's own live MCP runs.
        nohup setsid keyctl session "$KEYCTL_SESSION_NAME" bash -c "
            xvfb-run -a env \
                SLINT_MCP_PORT=$MCP_PORT \
                SLINT_BACKEND=winit-femtovg \
                CONMAN_DB_PATH='$DB_PATH' \
                ${SEED_JSON:+CONMAN_AUTOIMPORT='$SEED_JSON'} \
                '$BINARY'
        " > "$LOG_FILE" 2>&1 < /dev/null &
        disown
        READY=0
        for _ in $(seq 1 150); do
            (exec 3<>"/dev/tcp/127.0.0.1/$MCP_PORT") 2>/dev/null && { exec 3>&- 3<&-; READY=1; break; }
            sleep 0.2
        done
        if [ "$READY" -ne 1 ]; then
            line "FAIL -- conman/MCP server never came up on 127.0.0.1:$MCP_PORT, see $LOG_FILE"
            cat "$LOG_FILE"
        fi
    fi
    mkdir -p "$OUT_DIR/mcp-evidence"
    python3 "$REPO_ROOT/scripts/qa-gate-mcp.py" \
        --port "$MCP_PORT" --out-dir "$OUT_DIR/mcp-evidence" \
        --transcript "$OUT_DIR/mcp-evidence/transcript.txt" \
        --report-out "$OUT_DIR/mcp-report.json" \
        ${SSH_HOST:+--ssh-host "$SSH_HOST"} \
        ${SSH_USER:+--ssh-user "$SSH_USER"} \
        ${SSH_KEY_PATH:+--ssh-key-path "$SSH_KEY_PATH"} \
        ${TREE_SSH_LABEL:+--tree-ssh-label "$TREE_SSH_LABEL"} \
        ${TREE_RDP_LABEL:+--tree-rdp-label "$TREE_RDP_LABEL"} \
        ${RDP_TARGET_SSH_HOST:+--rdp-target-ssh-host "$RDP_TARGET_SSH_HOST"} \
        ${RDP_TARGET_SSH_USER:+--rdp-target-ssh-user "$RDP_TARGET_SSH_USER"} \
        > "$OUT_DIR/mcp-stdout.json" 2>"$OUT_DIR/mcp-stderr.log"
    MCP_STATUS=$?
    cat "$OUT_DIR/mcp-stderr.log" | tee -a "$SUMMARY"
    [ "$MCP_STATUS" -eq 0 ] && line "OVERALL: PASS (report: $OUT_DIR/mcp-report.json)" \
        || line "OVERALL: FAIL (report: $OUT_DIR/mcp-report.json)"

fi

# ---------------------------------------------------------------------------
# (c) Thin visual (render-correctness) layer -- advisory
# ---------------------------------------------------------------------------
section "(c) Visual checks (advisory)"
if [ "$SKIP_VISUAL" -eq 1 ]; then
    line "SKIPPED (--skip-visual)"
else
    if [ "$SKIP_LINUX_LAUNCH" -eq 0 ] && [ "$SKIP_MCP" -eq 1 ]; then
        line "SKIPPED -- visual checks need a live MCP session; pass --mcp-port against an already-running instance, or drop --skip-mcp"
    else
        mkdir -p "$OUT_DIR/visual-evidence"
        python3 "$REPO_ROOT/scripts/qa-gate-visual.py" \
            --port "$MCP_PORT" --out-dir "$OUT_DIR/visual-evidence" \
            --report-out "$OUT_DIR/visual-report.json" "$THEME_FLAG" \
            > "$OUT_DIR/visual-stdout.json" 2>"$OUT_DIR/visual-stderr.log"
        VISUAL_STATUS=$?
        cat "$OUT_DIR/visual-stderr.log" | tee -a "$SUMMARY"
        [ "$VISUAL_STATUS" -eq 0 ] && line "OVERALL: PASS (report: $OUT_DIR/visual-report.json)" \
            || line "OVERALL: FAIL/advisory (report: $OUT_DIR/visual-report.json) -- re-read: hard-fail only if a functional/#1-class regression, agent-vision is always advisory"
    fi
fi

# Keep the locally launched process alive through both real-binary legs.  The
# visual checks use the same MCP endpoint as the journey checks, so stopping it
# at the end of section (b) made every combined Linux gate report a spurious
# visual transport failure.
if [ "$SKIP_LINUX_LAUNCH" -eq 0 ] && [ "$SKIP_MCP" -eq 0 ]; then
    pkill -f -x "$BINARY" 2>/dev/null
    sleep 0.3
    pkill -KILL -f -x "$BINARY" 2>/dev/null
    line "stopped conman ($BINARY)"
fi

section "Evidence"
line "All artifacts under: $OUT_DIR"
echo
cat "$SUMMARY"
