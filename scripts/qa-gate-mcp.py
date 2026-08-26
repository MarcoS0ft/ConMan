#!/usr/bin/env python3
"""P8.4 -- the MCP-driven "real binary" journey script.

Builds on P8.3's `scripts/mcp-scenario-driver.py` (same JSON-RPC-over-HTTP
client, same element-tree-by-accessible-label pattern) to drive the REAL,
running `conman` (or `conman.exe`) binary through the journeys the P6.17
acceptance pass drove through legacy automation, now addressed semantically
instead of by screen coordinates:

  1. quick-connect SSH (public-key auth) to a loopback/fixture host, reaching
     Connected (P6.17 Linux J4 / Windows SSH-probe).
  2. credentialed tree-launch (SSH): click a saved, credential-bound
     connection row and reach Connected without ever typing a secret (P6.17
     J10, "P6.4 path").
  3. credentialed tree-launch (RDP) to a live target, reaching Connected --
     asserts the tab's status pill reads Connected ("Connected with success"
     is the ironrdp log line the P6.17/win-ui memos anchor on; this script
     doesn't grep the log, that's the coordinator's evidence-gathering step
     over the same SSH/console access used for the precheck below). Runs a
     TARGET-SIDE PRECHECK first (a cert bound to RDP-Tcp, and either NLA off
     -- the original win-ui-investigation memo recommendation, plain-TLS path
     -- or NLA on -- P9.1's CredSSP/NTLM path, also an expect-success
     configuration now) over a plain `ssh` call, so a failure here is
     attributable to a real client regression, not target config drift.
  4. reconnect: drops the RDP session on the target (`tsdiscon`) and clicks
     the app's own Reconnect button, reasserting Connected -- and reasons
     about "no cert re-prompt" the only way possible over this element
     surface: if the app were blocked waiting on a fresh Accept/Reject on a
     cert dialog this script never drives, the status would never reach
     Connected within the poll window, so reaching Connected on its own is
     the proof of no re-prompt (recorded explicitly in the step's note, not
     asserted by property-peeking a dialog-open flag the MCP surface doesn't
     expose).

## Why RDP is driven via tree-launch, never via a typed Quick Connect password
Learned by hand against a live app (recorded in `memos/P8.4-qa-gate-rubric.md`):
`FormField`'s PASSWORD variant (`components.slint`) binds `accessible-value`
to a hardcoded `""` (P8.1b's deliberate security carve-out -- a password
field must never let *reading* the accessible surface leak the cleartext).
That is a plain, non-two-way binding, so it is also not *writable* through
`set_element_value` -- there is no element on a Quick Connect RDP or
password-auth-SSH form this script can type a password into. This is a real,
permanent architectural boundary, not a script bug: it is exactly the class
of "undrivable without product code" case CONVENTIONS §3.5 asks to report
rather than route around with a product change. The credentialed tree-launch
path (P6.4/P6.17 J10 pattern -- the secret is resolved from the keychain via
an imported credential, never typed) sidesteps it entirely and is, in fact,
the *more* representative real-world path for a saved connection anyway.
Quick Connect over MCP therefore only ever demonstrates non-secret auth here
(SSH public-key with an unencrypted key, or Local).

Every step is independent and never raises past its own function -- each
records its own pass/fail/skipped/unverified entry into the shared report so
one broken step (e.g. no reachable RDP target) does not abort the rest. Output
is a single JSON report on stdout (and optionally --report-out) plus a
human-readable summary on stderr; exit code is 0 only if every attempted step
passed (skipped/unverified steps do not fail the exit code -- the caller
reads the report to see which).

Usage (seed a CONMAN_AUTOIMPORT JSON with the tree-launch connections BEFORE
launching conman -- see scripts/qa-gate.sh, which wires this up end-to-end):
    scripts/qa-gate-mcp.py --port 48900 --out-dir /tmp/out \\
        --ssh-host 127.0.0.1 --ssh-user <ssh-user> --ssh-key-path <ssh-key> \\
        --tree-ssh-label p84-tree-ssh --tree-rdp-label p84-tree-rdp \\
        --rdp-target-ssh-host <rdp-target-ip> --rdp-target-ssh-user <rdp-target-user> \\
        --report-out /tmp/out/mcp-report.json
"""
from __future__ import annotations

import argparse
import http.client
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

_driver_spec = importlib.util.spec_from_file_location(
    "mcp_scenario_driver", Path(__file__).resolve().parent / "mcp-scenario-driver.py"
)
if _driver_spec is None or _driver_spec.loader is None:
    raise ImportError(
        "could not load scripts/mcp-scenario-driver.py: "
        "importlib.util.spec_from_file_location returned no spec/loader"
    )
_driver = importlib.util.module_from_spec(_driver_spec)
_driver_spec.loader.exec_module(_driver)
McpClient = _driver.McpClient
McpError = _driver.McpError


class Report:
    def __init__(self) -> None:
        self.steps: list[dict] = []

    def record(self, step_id: str, status: str, detail: str) -> None:
        self.steps.append({"step": step_id, "status": status, "detail": detail})
        print(f"[{status.upper():10}] {step_id}: {detail}", file=sys.stderr)

    def ok(self) -> bool:
        return all(s["status"] in ("pass", "skip", "unverified") for s in self.steps)

    def to_json(self) -> str:
        return json.dumps({"steps": self.steps}, indent=2)


# ---------------------------------------------------------------------------
# Element-tree helpers
# ---------------------------------------------------------------------------

def find_one(elements: list[dict], **match) -> dict | None:
    for e in elements:
        if all(e.get(k) == v for k, v in match.items()):
            return e
    return None


def get_tree(client: McpClient, window_handle: str) -> list[dict]:
    return client.call_tool_json(
        "get_element_tree", {"elementHandle": window_handle, "maxElements": 4000}
    ).get("elements", [])


def get_window(client: McpClient) -> str:
    handles = client.call_tool_json("list_windows")["windowHandles"]
    if not handles:
        raise McpError("list_windows returned no windows")
    return handles[0]


def click_by_id(client: McpClient, elements: list[dict], element_id: str) -> dict:
    el = next(
        (e for e in elements if any(t.get("id") == element_id for t in e.get("typeNamesAndIds", []))),
        None,
    )
    if el is None:
        raise McpError(f"element id {element_id!r} not found in current tree")
    client.call_tool("click_element", {"elementHandle": el["handle"]})
    return el


def click_by_label(client: McpClient, elements: list[dict], label: str, role: str | None = None) -> dict:
    match = {"accessibleLabel": label}
    if role:
        match["accessibleRole"] = role
    el = find_one(elements, **match)
    if el is None:
        raise McpError(f"no element with accessibleLabel={label!r} role={role!r}")
    client.call_tool("click_element", {"elementHandle": el["handle"]})
    return el


def set_value_by_label(client: McpClient, elements: list[dict], label: str, value: str) -> None:
    """The ONLY correct way to reach a `FormField`'s real input (learned the
    hard way against a live app): the id given at a call site
    (`qc-host-field := FormField {...}`) is the id of `FormField` itself,
    which carries NO `accessible-role`/`accessible-label` of its own
    (`components.slint`'s `FormField` puts those on its *inner* `edit :=
    LineEdit`, whose compiled id is the unqualified `FormField::edit` --
    identical, and therefore useless as a unique target, across every
    `FormField` instance in the app). `set_element_value` against the outer
    id's handle returns success but is a silent no-op -- the dialog looks
    filled-in in no way at all, `qc-connect-btn`'s validation guard
    (`host.is_empty() || username.is_empty()`) trivially fails, and Connect
    quietly does nothing (confirmed directly: a whole scripted run "passed"
    on a false-positive Connected read from the ever-present, always-honest
    empty/Launchpad tab before this was caught and fixed). The only element
    that actually carries the real two-way `text` binding is the inner
    input, addressed by its `accessible-label` (the human field label, e.g.
    "HOST"/"USERNAME"/"PRIVATE KEY") + `accessible-role: TextInput` -- the
    same pattern P8.3's own `mcp-scenario-driver.py::is_host_field` already
    used, which this function generalizes. NOTE: password-type fields
    (P8.1b's carve-out) bind `accessible-value` to a hardcoded `""`, not `<=>
    text` -- this function cannot and must not be used for PASSWORD/
    PASSPHRASE fields; see the module docstring's "why RDP is driven via
    tree-launch" note."""
    el = find_one(elements, accessibleLabel=label, accessibleRole="TextInput")
    if el is None:
        raise McpError(f"no TextInput with accessibleLabel={label!r} found for set_element_value")
    client.call_tool("set_element_value", {"elementHandle": el["handle"], "value": value})


# A real running app under a genuine (winit) event loop needs at least one
# more render tick after a click that opens a dialog or swaps a conditional
# `if`-instantiated subtree before that subtree shows up in
# `get_element_tree` -- confirmed by hand against a live xvfb `conman`: an
# immediate re-query after `click_element` on "Quick connect" intermittently
# raced the dialog's own instantiation (found nothing), while the identical
# click plus a short wait reliably found it -- and how long that wait needs
# to be is itself load-dependent (a concurrent real SSH/RDP session
# competing for the same xvfb process's render ticks measurably slows it
# down). So this is a bounded POLL for the expected element, not a fixed
# sleep -- the real-binary analogue of the in-process suites' `pump_until`
# after `invoke_accessible_default_action()` on a kind-switch tab, except
# there is no mock clock to step here, only real wall-clock retries.
def wait_for_element(client: McpClient, window_handle: str, timeout: float = 8.0, **match) -> dict:
    deadline = time.monotonic() + timeout
    last_seen = 0
    while time.monotonic() < deadline:
        elements = get_tree(client, window_handle)
        last_seen = len(elements)
        hit = find_one(elements, **match)
        if hit is not None:
            return hit
        time.sleep(0.3)
    raise McpError(f"timed out after {timeout}s waiting for element matching {match!r} ({last_seen} elements in last tree)")


def click_id_until(
    client: McpClient, window_handle: str, element_id: str, wait_match: dict, attempts: int = 3, per_attempt_timeout: float = 4.0
) -> dict:
    """`click_by_id` then [`wait_for_element`], retried whole (re-fetch tree,
    re-click by id, re-wait) up to `attempts` times. Observed live against a
    real xvfb `conman` with an already-open remote session: a single
    click-then-wait on "Quick connect" occasionally didn't open the dialog at
    all within a generous window (not a render-tick race `wait_for_element`
    alone would cover -- the click itself needs re-issuing), while a second
    identical click did. Documented here as an honest real-binary robustness
    measure, not silently retried away -- each attempt beyond the first is
    recorded by the caller via the returned attempt count."""
    last_err: McpError | None = None
    for attempt in range(1, attempts + 1):
        try:
            elements = get_tree(client, window_handle)
            click_by_id(client, elements, element_id)
            hit = wait_for_element(client, window_handle, timeout=per_attempt_timeout, **wait_match)
            hit["_attempts"] = attempt
            return hit
        except McpError as e:
            last_err = e
    raise McpError(f"click_id_until({element_id!r}) failed after {attempts} attempts: {last_err}")


def status_pill_label(client: McpClient, window_handle: str) -> str:
    # The status pill's own accessible-label always starts with
    # "Connected"/"Connecting"/"Failed"/"Disconnected" (see
    # suite_shell.rs::status_pill_tracks_session_status).
    elements = get_tree(client, window_handle)
    for e in elements:
        label = e.get("accessibleLabel") or ""
        if label.startswith(("Connected", "Connecting", "Failed", "Disconnected")):
            return label
    return ""


def select_last_tab(client: McpClient, window_handle: str) -> bool:
    """`tabs::push_tab` (controller/tabs.rs) sets the newly-opened tab active
    at the Rust-model level immediately (`st.active = st.tabs.len() - 1` +
    `ui.set_active_tab(...)`), but this journey's status-pill checks must
    still target the RIGHT tab explicitly rather than assume it stayed
    focused across several more MCP round-trips -- reselecting the
    highest-index `AppWindow::tab-item` (the tab strip's `for` loop emits
    tabs in model/creation order, so the last one in the list is the most
    recently opened) before reading the status pill is what makes every
    check below deterministic regardless of what else the window is showing.
    Returns whether a tab was found and clicked."""
    elements = get_tree(client, window_handle)
    tabs = [
        e for e in elements if any(t.get("id") == "AppWindow::tab-item" for t in e.get("typeNamesAndIds", []))
    ]
    if not tabs:
        return False
    last = tabs[-1]
    client.call_tool("invoke_accessibility_action", {"elementHandle": last["handle"], "action": "Default_"})
    return True


def poll_status_prefix(client: McpClient, window_handle: str, prefix: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        label = status_pill_label(client, window_handle)
        if label.startswith(prefix):
            return True
        time.sleep(0.5)
    return False


def ssh_run(user: str, host: str, command: str, timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", f"{user}@{host}", command],
        capture_output=True, text=True, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Journeys
# ---------------------------------------------------------------------------

def step_quick_connect_ssh(client: McpClient, window_handle: str, report: Report, args) -> None:
    """Quick Connect, public-key auth (an unencrypted key -- no passphrase
    field to fill; see the module docstring for why password auth isn't
    driven this way)."""
    step = "mcp:quick-connect-ssh"
    if not (args.ssh_host and args.ssh_key_path):
        report.record(step, "skip", "no --ssh-host/--ssh-key-path given")
        return
    try:
        opened = click_id_until(
            client, window_handle, "AppWindow::quick-connect-btn",
            {"accessibleLabel": "New SSH connection dialog"},
        )
        if opened.get("_attempts", 1) > 1:
            report.record(step + ":click-retry", "pass", f"Quick connect needed {opened['_attempts']} click attempts to open")

        elements = get_tree(client, window_handle)
        set_value_by_label(client, elements, "HOST", args.ssh_host)
        set_value_by_label(client, elements, "USERNAME", args.ssh_user)
        click_by_label(client, elements, "Public key", role="Tab")
        wait_for_element(client, window_handle, accessibleRole="TextInput", accessibleLabel="PRIVATE KEY")
        elements = get_tree(client, window_handle)
        set_value_by_label(client, elements, "PRIVATE KEY", args.ssh_key_path)
        click_by_id(client, elements, "QuickConnectForm::qc-connect-btn")

        # An unknown host key may TOFU-prompt -- accept it if so (truthful
        # fingerprint verification is the visual/MCP-transcript's job, not
        # this functional step's).
        time.sleep(1.0)
        elements = get_tree(client, window_handle)
        accept = find_one(elements, accessibleLabel="Accept & continue")
        if accept is not None:
            client.call_tool("click_element", {"elementHandle": accept["handle"]})
            report.record(step + ":hostkey-tofu", "pass", "unknown host key accepted")

        select_last_tab(client, window_handle)
        if poll_status_prefix(client, window_handle, "Connected", args.connect_timeout):
            report.record(step, "pass", f"reached Connected to {args.ssh_host}")
        else:
            report.record(
                step, "fail",
                f"did not reach Connected within {args.connect_timeout}s (last={status_pill_label(client, window_handle)!r})",
            )
    except McpError as e:
        report.record(step, "fail", str(e))


def step_tree_launch(client: McpClient, window_handle: str, report: Report, args, conn_label: str | None, step: str) -> bool:
    """Click a saved, credential-bound connection row in the CONNECTIONS
    tree (needs CONMAN_AUTOIMPORT-seeded data -- see scripts/qa-gate.sh) and
    reach Connected without this script ever handling a secret. Shared by
    the SSH tree-launch journey (P6.17 J10) and the RDP journey (the
    password-carve-out workaround; see module docstring)."""
    if not conn_label:
        report.record(step, "skip", "no matching --tree-*-label given (needs CONMAN_AUTOIMPORT-seeded data)")
        return False
    try:
        row = wait_for_element(client, window_handle, timeout=5.0, accessibleRole="ListItem", accessibleLabel=conn_label)
    except McpError:
        # accessibleLabel on a ConnRow is name + extra metadata in general;
        # fall back to substring match once before giving up.
        elements = get_tree(client, window_handle)
        row = next(
            (e for e in elements if e.get("accessibleRole") == "ListItem" and conn_label in (e.get("accessibleLabel") or "")),
            None,
        )
        if row is None:
            report.record(step, "fail", f"no ListItem row labeled (or containing) {conn_label!r} found")
            return False
    try:
        # 'Default_' is the MCP tool's literal action name for "activate"
        # (mcp_server.rs's invoke_accessibility_action doc: "'Default_'
        # (activate buttons, toggle checkboxes)").
        client.call_tool("invoke_accessibility_action", {"elementHandle": row["handle"], "action": "Default_"})
        select_last_tab(client, window_handle)

        # A fresh host (first tree-launch to it this run) may TOFU-prompt a
        # host-key or RDP-cert dialog -- poll a bounded window for either
        # (independent of the tab's own status, which reads "Connecting"
        # near-instantly regardless of whether a TOFU dialog is about to
        # show -- racing the two was observed to make this miss a real cert
        # dialog and hang at "Connecting" for the full connect-timeout).
        # Already-trusted hosts (e.g. the SSH tree-launch reusing 127.0.0.1,
        # already accepted by the earlier quick-connect step) simply never
        # show a dialog and this loop harmlessly runs out its clock.
        tofu_deadline = time.monotonic() + 6.0
        while time.monotonic() < tofu_deadline:
            elements = get_tree(client, window_handle)
            accept = find_one(elements, accessibleLabel="Accept & continue") or find_one(
                elements, accessibleLabel="Accept & remember"
            )
            if accept is not None:
                client.call_tool("click_element", {"elementHandle": accept["handle"]})
                report.record(step + ":tofu", "pass", "unknown host-key/cert TOFU-accepted")
                break
            time.sleep(0.3)

        if poll_status_prefix(client, window_handle, "Connected", args.connect_timeout):
            report.record(step, "pass", f"credentialed launch of {conn_label!r} reached Connected (no secret typed)")
            return True
        report.record(
            step, "fail",
            f"did not reach Connected within {args.connect_timeout}s (last={status_pill_label(client, window_handle)!r})",
        )
        return False
    except McpError as e:
        report.record(step, "fail", str(e))
        return False


def target_precheck(args, report: Report) -> None:
    """Check cert-bound + a known-supported security mode on the RDP TARGET
    over plain ssh before attempting a connect, so a failure is attributable
    to the client, not target-config drift.

    P9.1 (CredSSP/NLA support) made both `UserAuthentication` values a
    supported, expect-success configuration: NLA off (`0`, the original
    win-ui-investigation memo recommendation -- plain TLS path, unchanged)
    and NLA on (`1` -- exercises the new CredSSP/NTLM path). Only the legacy
    Standard RDP Security case (no enhanced-security layer at all) remains
    unsupported by design; this PowerShell probe can't directly observe that
    (it only reads the NLA flag, not the negotiated security layer), so it is
    not distinguished here -- a target with NLA off and `SecurityLayer` also
    forced to legacy RDP would still report NLA=0 and pass this precheck, then
    fail the actual connect with `RdpError::LegacySecurityOnly` (see
    `docs/devel/memos/rdp-xrdp-diagnosis-2026-07.md`)."""
    step = "mcp:rdp-target-precheck"
    if not args.rdp_target_ssh_host:
        report.record(step, "skip", "no --rdp-target-ssh-host given")
        return
    if not args.rdp_target_ssh_user:
        report.record(step, "skip", "no --rdp-target-ssh-user given (required with --rdp-target-ssh-host)")
        return
    try:
        rdp_tcp = "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
        ps = (
            f"$nla = Get-ItemPropertyValue '{rdp_tcp}' -Name UserAuthentication; "
            f"$cert = Get-ItemPropertyValue '{rdp_tcp}' -Name SSLCertificateSHA1Hash; "
            "Write-Output \"NLA=$nla\"; "
            # SSLCertificateSHA1Hash is a byte array -- render as one hex
            # string, not PowerShell's default one-decimal-per-line array
            # dump (which silently truncated to the first byte, "173", the
            # first time this precheck ran against a real target).
            "Write-Output ('CERT=' + (($cert | ForEach-Object { $_.ToString('X2') }) -join ''))"
        )
        out = ssh_run(args.rdp_target_ssh_user, args.rdp_target_ssh_host, ps)
        nla = next((l.split("=", 1)[1] for l in out.stdout.splitlines() if l.startswith("NLA=")), "?")
        cert = next((l.split("=", 1)[1] for l in out.stdout.splitlines() if l.startswith("CERT=")), "")
        if nla in ("0", "1") and cert:
            mode = "NLA off (UserAuthentication=0), plain-TLS path" if nla == "0" \
                else "NLA on (UserAuthentication=1), CredSSP/NTLM path (P9.1)"
            report.record(step, "pass", f"target precheck OK: {mode}, cert bound ({cert})")
        else:
            report.record(
                step, "fail",
                f"target precheck FAILED: UserAuthentication={nla!r} SSLCertificateSHA1Hash={cert!r} -- "
                "a subsequent RDP failure is target-config drift, not a client regression",
            )
    except Exception as e:  # noqa: BLE001 -- best-effort diagnostic, never fatal
        report.record(step, "unverified", f"could not run target precheck over ssh: {e}")


def step_rdp_reconnect(client: McpClient, window_handle: str, report: Report, args) -> None:
    step = "mcp:rdp-reconnect"
    if not args.rdp_target_ssh_host:
        report.record(step, "skip", "no --rdp-target-ssh-host given (needed to force a drop)")
        return
    if not args.rdp_target_ssh_user:
        report.record(step, "skip", "no --rdp-target-ssh-user given (required with --rdp-target-ssh-host)")
        return
    try:
        if not select_last_tab(client, window_handle):
            report.record(step, "fail", "no tab to reselect before forcing the drop (RDP tab may already be gone)")
            return

        ssh_run(args.rdp_target_ssh_user, args.rdp_target_ssh_host, "tsdiscon 1")

        if not poll_status_prefix(client, window_handle, "Disconnected", 15) and not poll_status_prefix(
            client, window_handle, "Failed", 5
        ):
            report.record(
                step, "fail",
                f"forced drop (tsdiscon 1) did not surface as Disconnected/Failed within 20s "
                f"(last pill={status_pill_label(client, window_handle)!r})",
            )
            return

        elements = get_tree(client, window_handle)
        reconnect_btn = next(
            (e for e in elements if any(t.get("id") == "ErrorOverlay::error-reconnect-btn" for t in e.get("typeNamesAndIds", []))),
            None,
        )
        if reconnect_btn is None:
            report.record(step, "fail", "no ErrorOverlay::error-reconnect-btn in tree after the forced drop")
            return
        client.call_tool("click_element", {"elementHandle": reconnect_btn["handle"]})

        if poll_status_prefix(client, window_handle, "Connected", args.connect_timeout):
            report.record(
                step, "pass",
                "Reconnect reached Connected again WITHOUT this script driving a fresh cert Accept -- "
                "the only way that's possible is if no re-prompt occurred (a re-prompt would have blocked "
                "the connect on an Accept/Reject this script never clicked, and Connected would never appear)",
            )
        else:
            report.record(step, "fail", f"Reconnect did not reach Connected within {args.connect_timeout}s")
    except Exception as e:  # noqa: BLE001
        report.record(step, "fail", f"reconnect step errored: {e}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--report-out", default=None)
    ap.add_argument("--transcript", default=None)
    ap.add_argument("--connect-timeout", type=float, default=25.0)

    ap.add_argument("--ssh-host", default=None)
    ap.add_argument("--ssh-user", default=None)
    ap.add_argument("--ssh-key-path", default=None, help="Quick Connect public-key auth (unencrypted key)")

    ap.add_argument("--tree-ssh-label", default=None, help="CONMAN_AUTOIMPORT-seeded SSH connection name")
    ap.add_argument("--tree-rdp-label", default=None, help="CONMAN_AUTOIMPORT-seeded RDP connection name")

    ap.add_argument("--rdp-target-ssh-host", default=None)
    ap.add_argument("--rdp-target-ssh-user", default=None,
                    help="SSH user on the RDP target host (for the precheck); required only when --rdp-target-ssh-host is given")

    args = ap.parse_args()

    Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    report = Report()

    deadline = time.monotonic() + 30.0
    up = False
    while time.monotonic() < deadline:
        try:
            conn = http.client.HTTPConnection(args.host, args.port, timeout=2)
            conn.connect()
            conn.close()
            up = True
            break
        except OSError:
            time.sleep(0.2)
    if not up:
        print(f"qa-gate-mcp: MCP server never came up on {args.host}:{args.port}", file=sys.stderr)
        return 2

    client = McpClient(args.host, args.port, args.transcript)
    try:
        client.initialize()
        window_handle = get_window(client)

        step_quick_connect_ssh(client, window_handle, report, args)
        step_tree_launch(client, window_handle, report, args, args.tree_ssh_label, "mcp:credentialed-tree-launch-ssh")
        target_precheck(args, report)
        rdp_ok = step_tree_launch(client, window_handle, report, args, args.tree_rdp_label, "mcp:credentialed-tree-launch-rdp")
        if rdp_ok:
            step_rdp_reconnect(client, window_handle, report, args)
        else:
            report.record("mcp:rdp-reconnect", "skip", "RDP tree-launch did not succeed; nothing to reconnect")
    finally:
        client.close()

    out = report.to_json()
    if args.report_out:
        Path(args.report_out).write_text(out)
    print(out)
    return 0 if report.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
