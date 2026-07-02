#!/usr/bin/env python3
"""P6.2b Part A — JSON-lines driver for the in-app QA endpoint.

Speaks the protocol pinned in docs/devel/tasks/P6.2b-remote-qa-harness.md over
a plain TCP socket (works identically against the local xvfb instance from
scripts/qa-scenario.sh, or a Windows box reached over an SSH port-forward in
Part B — the protocol does not care which). Not a general-purpose library:
kept small and dependency-free (stdlib only) so it runs on any Python3.

Exit code 0 = every step in the scenario passed; non-zero = the first failing
step's message is printed to stderr.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time


class QaClient:
    def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._rfile = self._sock.makefile("r", encoding="utf-8", newline="\n")

    def send(self, request: dict) -> dict:
        line = json.dumps(request) + "\n"
        self._sock.sendall(line.encode("utf-8"))
        reply_line = self._rfile.readline()
        if not reply_line:
            raise RuntimeError(f"qa socket closed while waiting for a reply to {request!r}")
        return json.loads(reply_line)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def expect_ok(step: str, reply: dict) -> dict:
    if not reply.get("ok"):
        raise AssertionError(f"{step}: expected ok=true, got {reply!r}")
    return reply


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--theme", default="dark")
    ap.add_argument(
        "--shot-path",
        default=None,
        help=(
            "Path passed verbatim to the {\"cmd\":\"screenshot\"} request, on the "
            "filesystem of the machine actually running conman (not necessarily this "
            "one) — e.g. a Windows path when driving Part B's runner over an SSH "
            "port-forward (scripts/qa-win.sh). Defaults to "
            "<out-dir>/qa-scenario-<theme>.png (this machine == the QA target)."
        ),
    )
    args = ap.parse_args()

    client = QaClient(args.host, args.port)
    try:
        # 1. state — a local tab should already be open at startup.
        reply = expect_ok("state (initial)", client.send({"cmd": "state"}))
        tabs = reply["state"]["tabs"]
        if not tabs:
            raise AssertionError(f"state: expected at least one open tab, got {tabs!r}")
        print(f"[qa-scenario] initial state: {len(tabs)} tab(s), "
              f"active_panel={reply['state']['active_panel']}")

        # 2. type a probe command into the active (local) tab.
        expect_ok("text probe", client.send({"cmd": "text", "text": "echo MARK42"}))
        expect_ok("key Enter", client.send({"cmd": "key", "code": "Enter"}))

        # Give the local shell a moment to echo before screenshotting — this
        # is PTY-process latency, not QA-protocol sequencing (the protocol
        # itself never needs a sleep: every reply already waits for the UI
        # work to finish).
        time.sleep(0.5)

        # 3. state again — still exactly one tab, still on the same panel.
        reply2 = expect_ok("state (after probe)", client.send({"cmd": "state"}))
        if len(reply2["state"]["tabs"]) != len(tabs):
            raise AssertionError("state: tab count changed unexpectedly after typing a probe")

        # 4. screenshot.
        shot_path = args.shot_path or f"{args.out_dir}/qa-scenario-{args.theme}.png"
        reply3 = expect_ok(
            "screenshot", client.send({"cmd": "screenshot", "path": shot_path})
        )
        if reply3.get("width", 0) <= 0 or reply3.get("height", 0) <= 0:
            raise AssertionError(f"screenshot: non-positive dimensions in {reply3!r}")
        print(f"[qa-scenario] screenshot: {reply3['width']}x{reply3['height']} -> {shot_path}")

        # 5. malformed-JSON fail-soft check (never a panic; app must reply
        # with ok=false and keep the socket open for the next command).
        client._sock.sendall(b"{not json\n")
        bad_reply_line = client._rfile.readline()
        bad_reply = json.loads(bad_reply_line)
        if bad_reply.get("ok"):
            raise AssertionError(f"malformed JSON: expected ok=false, got {bad_reply!r}")
        print("[qa-scenario] malformed JSON correctly rejected without a panic")

        # 6. quit.
        expect_ok("quit", client.send({"cmd": "quit"}))
        print("[qa-scenario] quit acknowledged")
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, RuntimeError, OSError) as exc:
        print(f"[qa-scenario] FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
