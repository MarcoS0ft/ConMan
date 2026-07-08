#!/usr/bin/env python3
"""P8.3 — JSON-RPC driver for the Slint-native MCP automation surface.

Speaks plain HTTP + single JSON-RPC (MCP "Streamable HTTP" transport, POST-only
mode) to `i-slint-backend-testing`'s embedded MCP server
(`mcp_server.rs`, vendored at
`i-slint-backend-testing-1.17.0/mcp_server.rs`), reached over
`http://127.0.0.1:<port>/mcp` — identical whether that port is a direct local
connection (scripts/mcp-run.sh) or the far end of an SSH local-forward onto
win11-dev (scripts/mcp-win.sh). Stdlib-only (no `requests`/`mcp` SDK dependency)
so it runs anywhere Python3 does.

Runs the DoD's core smoke sequence per docs/devel/tasks/P8.3-mcp-automation-surface.md:
    initialize -> list_windows -> find the Quick Connect trigger by its
    accessible label ("Quick connect") -> click_element -> find the "HOST"
    field in the dialog that opens -> set_element_value -> get_element_properties
    (round-trip check) -> take_screenshot (PNG saved to --out-dir).

Every request/response pair is appended to --transcript (JSON-RPC bodies,
pretty-printed) so a run produces the transcript artifact the task's
verification section asks for. Exit code 0 = every step passed; non-zero on
the first failing step, with a message on stderr.

Usage:
    scripts/mcp-scenario-driver.py --port 48900 --out-dir /tmp/out \\
        --transcript /tmp/out/transcript.txt \\
        --host-value mark42-mcp-probe.lab
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import sys
import time
import urllib.request
import urllib.error


class McpError(RuntimeError):
    pass


class McpClient:
    """Minimal MCP Streamable-HTTP (POST-only) JSON-RPC client."""

    def __init__(self, host: str, port: int, transcript_path: str | None, timeout: float = 15.0) -> None:
        self._url = f"http://{host}:{port}/mcp"
        self._timeout = timeout
        self._next_id = 1
        self._transcript = open(transcript_path, "a", encoding="utf-8") if transcript_path else None

    def _log(self, label: str, payload) -> None:
        if not self._transcript:
            return
        self._transcript.write(f"=== {label} ===\n")
        if isinstance(payload, (bytes, bytearray)):
            self._transcript.write(f"[{len(payload)} bytes, not printed inline]\n")
        else:
            self._transcript.write(json.dumps(payload, indent=2, sort_keys=True))
            self._transcript.write("\n")
        self._transcript.flush()

    def _request(self, method: str, params: dict | None = None) -> dict:
        req_id = self._next_id
        self._next_id += 1
        body = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            body["params"] = params
        self._log(f"--> {method}", body)
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self._url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.URLError as e:
            raise McpError(f"{method}: transport error: {e}") from e
        parsed = json.loads(raw)
        # Log with any base64 image payloads elided (they're huge and not
        # human-useful in a transcript file).
        loggable = json.loads(raw)
        try:
            for c in loggable.get("result", {}).get("content", []):
                if c.get("type") == "image" and "data" in c:
                    c["data"] = f"<{len(c['data'])} base64 chars elided>"
        except AttributeError:
            pass
        self._log(f"<-- {method}", loggable)
        if "error" in parsed:
            raise McpError(f"{method}: JSON-RPC error: {parsed['error']!r}")
        return parsed["result"]

    def initialize(self) -> dict:
        return self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-scenario-driver", "version": "1.0"},
            },
        )

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        result = self._request("tools/call", {"name": name, "arguments": arguments or {}})
        if result.get("isError"):
            raise McpError(f"{name}: tool reported an error: {result!r}")
        return result

    def call_tool_json(self, name: str, arguments: dict | None = None) -> dict:
        """Call a tool whose sole text content block is a JSON object, and
        return it parsed."""
        result = self.call_tool(name, arguments)
        for c in result.get("content", []):
            if c.get("type") == "text":
                return json.loads(c["text"])
        raise McpError(f"{name}: no text content block in response: {result!r}")

    def close(self) -> None:
        if self._transcript:
            self._transcript.close()


def find_in_tree(elements: list[dict], predicate) -> dict | None:
    for e in elements:
        if predicate(e):
            return e
    return None


def is_quick_connect_button(e: dict) -> bool:
    ids = e.get("typeNamesAndIds", [])
    return (
        e.get("accessibleLabel") == "Quick connect"
        and e.get("accessibleRole") == "Button"
        and any(t.get("id") == "AppWindow::quick-connect-btn" for t in ids)
    )


def is_host_field(e: dict) -> bool:
    return e.get("accessibleLabel") == "HOST" and e.get("accessibleRole") == "TextInput"


def run_scenario(
    client: McpClient, out_dir: str, host_value: str, screenshot_name: str
) -> None:
    import os

    os.makedirs(out_dir, exist_ok=True)

    init = client.initialize()
    server_name = init.get("serverInfo", {}).get("name", "?")
    print(f"initialize: ok (server={server_name})")

    windows = client.call_tool_json("list_windows")
    handles = windows["windowHandles"]
    if not handles:
        raise McpError("list_windows returned no windows")
    window_handle = handles[0]
    print(f"list_windows: ok ({len(handles)} window(s))")

    tree = client.call_tool_json(
        "get_element_tree",
        {"elementHandle": window_handle, "maxElements": 1000},
    )
    elements = tree.get("elements", [])
    quick_connect = find_in_tree(elements, is_quick_connect_button)
    if quick_connect is None:
        raise McpError(
            "could not find the Quick Connect trigger by accessible label "
            "'Quick connect' (id AppWindow::quick-connect-btn) in the element tree"
        )
    print(f"find Quick Connect trigger by accessible label: ok (handle={quick_connect['handle']})")

    client.call_tool("click_element", {"elementHandle": quick_connect["handle"]})
    print("click_element: ok")

    # Re-query: clicking Quick Connect opens the QuickConnectForm dialog, which
    # did not exist in the tree before the click.
    tree_after = client.call_tool_json(
        "get_element_tree",
        {"elementHandle": window_handle, "maxElements": 1000},
    )
    host_field = find_in_tree(tree_after.get("elements", []), is_host_field)
    if host_field is None:
        raise McpError("could not find the HOST field after opening the Quick Connect dialog")
    print(f"find HOST field by accessible label: ok (handle={host_field['handle']})")

    client.call_tool(
        "set_element_value", {"elementHandle": host_field["handle"], "value": host_value}
    )
    print(f"set_element_value HOST={host_value!r}: ok")

    props = client.call_tool_json("get_element_properties", {"elementHandle": host_field["handle"]})
    if props.get("accessibleValue") != host_value:
        raise McpError(
            f"get_element_properties round-trip mismatch: expected {host_value!r}, "
            f"got {props.get('accessibleValue')!r}"
        )
    print(f"get_element_properties round-trip: ok (accessibleValue={props['accessibleValue']!r})")

    shot = client.call_tool("take_screenshot", {"windowHandle": window_handle})
    image_block = next((c for c in shot["content"] if c.get("type") == "image"), None)
    if image_block is None:
        raise McpError("take_screenshot returned no image content block")
    png_bytes = base64.b64decode(image_block["data"])
    out_path = f"{out_dir.rstrip('/')}/{screenshot_name}"
    with open(out_path, "wb") as f:
        f.write(png_bytes)
    print(f"take_screenshot: ok ({len(png_bytes)} bytes) -> {out_path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1", help="MCP server host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--transcript", default=None, help="append the full JSON-RPC transcript here")
    ap.add_argument("--host-value", default="mark42-mcp-probe.lab", help="value set into the HOST field")
    ap.add_argument("--screenshot-name", default="mcp-scenario.png")
    ap.add_argument("--wait-secs", type=float, default=30.0, help="bounded poll for the server to come up")
    args = ap.parse_args()

    # Bounded poll for the server to accept connections (process startup race
    # — mirrors scripts/qa-scenario.sh's pattern, not a fixed sleep).
    deadline = time.monotonic() + args.wait_secs
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            conn = http.client.HTTPConnection(args.host, args.port, timeout=2)
            conn.connect()
            conn.close()
            last_err = None
            break
        except OSError as e:
            last_err = e
            time.sleep(0.2)
    if last_err is not None:
        print(f"mcp-scenario-driver: server never came up on {args.host}:{args.port}: {last_err}", file=sys.stderr)
        return 1

    client = McpClient(args.host, args.port, args.transcript)
    try:
        run_scenario(client, args.out_dir, args.host_value, args.screenshot_name)
    except McpError as e:
        print(f"mcp-scenario-driver: FAIL: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()
    print("mcp-scenario-driver: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
