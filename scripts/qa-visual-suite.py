#!/usr/bin/env python3
"""P7.4 — repeatable visual-QA gate: dialog + geometry + reachability checks.

Speaks the same JSON-lines protocol as `qa-scenario-driver.py` (see
`crates/cm-ui/src/controller/qa_harness.rs`), against a single already-running
`qa-harness`-enabled `conman` instance (launch it yourself, or use
`qa-visual-suite.sh` to launch one per theme and run this against each).

Every check is a function `check_*(qa, out_dir) -> CheckResult` appended to
`CHECKS`. Each is independent (opens/closes its own dialogs) so a failure in
one does not cascade into false failures in the next. This suite is expected
to FAIL several checks against current master (P7.2/P7.3/P7.5's un-fixed
defects) BY DESIGN -- that is what proves the checks have teeth. See
docs/devel/memos/P7.4-visual-qa-rubric.md for what each check means, why the
pinned pixel coordinates/tokens are what they are, and the expected
pass/fail table before and after the P7.2/P7.3/P7.5 fixes land.

Usage:
    qa-visual-suite.py --port 47901 --theme light --out-dir /tmp/qa-shots

Exit code: 0 if the suite RAN to completion (every check produced a verdict);
non-zero only on a harness/protocol-level failure (can't connect, a command
errors when it shouldn't have, etc). Whether individual rubric checks PASS or
FAIL is reported in the JSON/table -- that is data, not a suite failure.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent


class QaClient:
    def __init__(self, host: str, port: int, timeout: float = 15.0, scratch_path: str | None = None) -> None:
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._rfile = self._sock.makefile("r", encoding="utf-8", newline="\n")
        # Where `settle()` writes its throwaway snapshot. Must be a real,
        # writable path on the machine actually running `conman` (not
        # necessarily this one -- e.g. a Windows path when driving Part B's
        # runner over an SSH port-forward) — never hardcode a Unix-only path
        # like `/dev/null` here, this suite also targets the win11-dev console.
        self.scratch_path = scratch_path or "qa-visual-suite-settle.png"

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

    # ── convenience wrappers over the raw protocol ──────────────────────

    def screenshot(self, path: str) -> dict:
        return self.send({"cmd": "screenshot", "path": path})

    def settle(self) -> None:
        """Slint's `take_snapshot()` can return a one-frame-stale buffer
        relative to a property change made in the immediately preceding
        command (observed empirically while building this suite -- see the
        rubric memo's "harness gotchas" section). Any check that mutates
        state and then asserts on pixels must call this first: it forces one
        extra render/snapshot cycle (discarded) so the next real screenshot
        or `pixel` call reflects the mutation."""
        self.send({"cmd": "screenshot", "path": self.scratch_path})

    def dialog_get(self, dialog: str, field: str) -> Any:
        r = self.send({"cmd": "dialog_field", "dialog": dialog, "field": field, "action": "get"})
        return r

    def dialog_set(self, dialog: str, field: str, value: Any) -> dict:
        return self.send(
            {"cmd": "dialog_field", "dialog": dialog, "field": field, "action": "set", "value": value}
        )

    def dialog_state(self, dialog: str) -> dict:
        return self.send({"cmd": "dialog_state", "dialog": dialog})

    def dialog_click(self, dialog: str, button: str) -> dict:
        return self.send({"cmd": "dialog_click", "dialog": dialog, "button": button})

    def palette(self, action: str) -> dict:
        return self.send({"cmd": "palette", "action": action})

    def pixel(self, regions: list[dict]) -> dict:
        return self.send({"cmd": "pixel", "regions": regions})

    def state(self) -> dict:
        return self.send({"cmd": "state"})

    def key(self, text: str | None = None, code: str | None = None, modifiers: list[str] | None = None) -> dict:
        req: dict = {"cmd": "key", "modifiers": modifiers or []}
        if text is not None:
            req["text"] = text
        if code is not None:
            req["code"] = code
        return self.send(req)


@dataclass
class CheckResult:
    name: str
    status: str  # "PASS" | "FAIL" | "SKIP" | "INFO"
    detail: str
    evidence: dict = field(default_factory=dict)


# ── theme tokens (crates/cm-ui/ui/theme.slint) — pinned, not derived live ──
# (the harness has no "read a Theme token" command; these are the exact
# literal values in theme.slint at P7.4 time. If a future palette/theme
# change edits these, re-pin here.)
TOKENS = {
    "light": {
        "color_overlay": (251, 250, 247),  # #fbfaf7 -- dialogs/palette/menus
        "color_elevated": (233, 236, 240),  # #e9ecf0 -- activity bar / side panel
        "text_secondary": (92, 99, 110),  # #5c636e
    },
    "dark": {
        "color_overlay": (28, 32, 39),  # #1c2027
        "color_elevated": (21, 24, 30),  # #15181e
        "text_secondary": (150, 156, 168),  # #969ca8
    },
}

# WCAG-style relative-luminance contrast ratio.
def _srgb_to_linear(c: int) -> float:
    c2 = c / 255.0
    return c2 / 12.92 if c2 <= 0.03928 else ((c2 + 0.055) / 1.055) ** 2.4


def _rel_luminance(rgb: tuple[int, int, int]) -> float:
    r, g, b = (_srgb_to_linear(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: tuple[int, int, int], bg: tuple[int, int, int]) -> float:
    l1, l2 = _rel_luminance(fg), _rel_luminance(bg)
    l1, l2 = max(l1, l2), min(l1, l2)
    return (l1 + 0.05) / (l2 + 0.05)


def _color_dist(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


# A pixel is considered "matches the token" when within this Euclidean RGB
# distance -- generous enough to absorb antialiasing/subpixel blending at a
# card's own edge, tight enough that a genuinely different color (e.g. scrim
# blended over arbitrary background content) never slips through. Calibrated
# empirically: exact-match cases measured 0 distance; mismatch cases measured
# 90-350+ (see the rubric memo's calibration notes).
MATCH_TOLERANCE = 20.0


def _sample_rgb(pixel_reply: dict, name: str) -> tuple[int, int, int] | None:
    s = pixel_reply.get("samples", {}).get(name)
    if not s or "error" in s:
        return None
    return (s["r"], s["g"], s["b"])


# ── checks ───────────────────────────────────────────────────────────────
# Each check opens the dialog(s) it needs, does its assertions, and leaves
# every dialog it opened closed again (so checks can run in any order without
# state bleeding between them).

# The two gutter points below are calibrated against master @ 8a7a621 (see
# the rubric memo): for the profile editor, opened via the "New RDP
# connection" palette action (kind pre-set to RDP, so the dialog is in its
# widest/tallest RDP shape); for quick-connect, opened via "Quick connect...",
# then kind set to RDP the same way an agent driving the SegmentedControl
# would. Both points land in the vertical gap between the TYPE control and
# the HOST field, comfortably inside where a properly-carded dialog's
# background would be.
GUTTER_POINTS = [
    {"name": "gutter_a", "x": 640, "y": 230, "w": 6, "h": 6},
    {"name": "gutter_b", "x": 890, "y": 300, "w": 4, "h": 4},
]


def check_dialog_enabler_demo(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """DoD demonstration: open the profile editor over the socket, type into
    a field, click Save/Cancel, assert the result via `dialog_state` +
    `state`, with a screenshot as visual proof. Not itself a rubric pass/fail
    on a UI defect -- this is "does the enabler actually work"."""
    qa.palette("New SSH connection")
    st = qa.dialog_state("profile_editor")
    if not st.get("open"):
        return CheckResult("dialog_enabler_demo", "FAIL", f"profile_editor did not open: {st}")

    qa.dialog_set("profile_editor", "name", "QA Suite Probe")
    qa.dialog_set("profile_editor", "host", "probe.example")
    qa.dialog_set("profile_editor", "username", "qa")
    qa.settle()
    shot = out_dir / f"enabler-demo-filled-{theme}.png"
    qa.screenshot(str(shot))

    after_fill = qa.dialog_state("profile_editor")
    name_ok = after_fill["fields"].get("name") == "QA Suite Probe"
    host_ok = after_fill["fields"].get("host") == "probe.example"

    qa.dialog_click("profile_editor", "cancel")
    qa.settle()
    st2 = qa.state()
    closed = "profile_editor_open" not in st2["state"]["open_overlays"]

    ok = name_ok and host_ok and closed
    detail = (
        f"typed name/host round-tripped via dialog_state ({name_ok=}, {host_ok=}); "
        f"cancel closed the dialog ({closed=}); screenshot: {shot.name}"
    )
    return CheckResult(
        "dialog_enabler_demo",
        "PASS" if ok else "FAIL",
        detail,
        {"screenshot": str(shot), "fields_after_fill": after_fill["fields"]},
    )


def check_field_manifest_rdp_port_default(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """P7.2 defect #2 (part 1): switching Type to RDP mid-edit should default
    Port to 3389 (QuickConnectForm does this reactively; ProfileEditor does
    not). Runs the identical recipe against both dialogs."""
    results = {}

    qa.palette("Quick connect…")
    qa.dialog_set("quick_connect", "kind", 0)  # start SSH (port defaults 22)
    before = qa.dialog_get("quick_connect", "port")["value"]
    qa.dialog_set("quick_connect", "kind", 1)  # switch to RDP
    after = qa.dialog_get("quick_connect", "port")["value"]
    results["quick_connect"] = {"before": before, "after": after, "ok": after == "3389"}
    qa.dialog_click("quick_connect", "cancel")

    qa.palette("New SSH connection")
    qa.dialog_set("profile_editor", "kind", 0)
    before2 = qa.dialog_get("profile_editor", "port")["value"]
    qa.dialog_set("profile_editor", "kind", 1)
    after2 = qa.dialog_get("profile_editor", "port")["value"]
    results["profile_editor"] = {"before": before2, "after": after2, "ok": after2 == "3389"}
    qa.dialog_click("profile_editor", "cancel")

    qc_ok = results["quick_connect"]["ok"]
    pe_ok = results["profile_editor"]["ok"]
    # The reported status tracks profile_editor -- the actual assertion this
    # check exists to make (per the spec: "per-kind field manifest ... catches
    # #2"). quick_connect is a positive control: it is already correct, so if
    # IT fails that means the harness/mechanism itself is broken (a distinct,
    # more severe problem than the known product defect), reported as ERROR
    # rather than folded into a plain FAIL.
    if not qc_ok:
        status = "ERROR"
    else:
        status = "PASS" if pe_ok else "FAIL"
    detail = (
        f"quick_connect kind SSH->RDP: port {before!r} -> {after!r} (expect 3389, {'OK' if qc_ok else 'BUG'}); "
        f"profile_editor kind SSH->RDP: port {before2!r} -> {after2!r} "
        f"(expect 3389, {'OK' if pe_ok else 'BUG -- P7.2 defect #2'})"
    )
    return CheckResult("field_manifest_rdp_port_default", status, detail, results)


def check_field_manifest_rdp_domain_resolution(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """P7.2 defect #2 (part 2): the RDP profile-editor form should expose
    Domain + Resolution fields (quick-connect's RDP form already does)."""
    qa.palette("Quick connect…")
    qa.dialog_set("quick_connect", "kind", 1)
    qc_domain = qa.dialog_get("quick_connect", "rdp_domain")
    qc_res = qa.dialog_get("quick_connect", "rdp_resolution")
    qa.dialog_click("quick_connect", "cancel")

    qa.palette("New RDP connection")
    pe_domain = qa.dialog_get("profile_editor", "domain")
    pe_res = qa.dialog_get("profile_editor", "resolution")
    qa.dialog_click("profile_editor", "cancel")

    qc_ok = qc_domain.get("ok") and qc_res.get("ok")
    pe_ok = pe_domain.get("ok") and pe_res.get("ok")
    # See check_field_manifest_rdp_port_default's comment: status tracks the
    # profile_editor assertion; quick_connect is the positive control.
    if not qc_ok:
        status = "ERROR"
    else:
        status = "PASS" if pe_ok else "FAIL"
    detail = (
        f"quick_connect RDP form has domain/resolution fields: {qc_ok} "
        f"(reads: {qc_domain.get('value')!r}/{qc_res.get('value')!r}); "
        f"profile_editor RDP form has domain/resolution fields: {pe_ok} "
        f"({'present' if pe_ok else 'ABSENT -- P7.2 defect #2 (' + pe_domain.get('error', '') + ')'})"
    )
    return CheckResult(
        "field_manifest_rdp_domain_resolution",
        status,
        detail,
        {"quick_connect": [qc_domain, qc_res], "profile_editor": [pe_domain, pe_res]},
    )


def check_dialog_opacity_bleedthrough(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """P7.2 defect #1: dialog gutter pixels should equal the panel/overlay
    token, not whatever is rendered behind the dialog. quick_connect has the
    correct opaque card; profile_editor does not."""
    tok = TOKENS[theme]["color_overlay"]
    out = {}

    qa.palette("Quick connect…")
    qa.dialog_set("quick_connect", "kind", 1)
    qa.settle()
    shot = out_dir / f"opacity-quick_connect-{theme}.png"
    qa.screenshot(str(shot))
    px = qa.pixel(GUTTER_POINTS)
    qc_samples = {r["name"]: _sample_rgb(px, r["name"]) for r in GUTTER_POINTS}
    qc_match = any(
        s is not None and _color_dist(s, tok) <= MATCH_TOLERANCE for s in qc_samples.values()
    )
    qa.dialog_click("quick_connect", "cancel")

    qa.palette("New RDP connection")
    qa.settle()
    shot2 = out_dir / f"opacity-profile_editor-{theme}.png"
    qa.screenshot(str(shot2))
    px2 = qa.pixel(GUTTER_POINTS)
    pe_samples = {r["name"]: _sample_rgb(px2, r["name"]) for r in GUTTER_POINTS}
    pe_match = any(
        s is not None and _color_dist(s, tok) <= MATCH_TOLERANCE for s in pe_samples.values()
    )
    qa.dialog_click("profile_editor", "cancel")

    # Status tracks profile_editor (the actual assertion this check exists to
    # make); quick_connect is the positive control -- see
    # check_field_manifest_rdp_port_default's comment for the rationale.
    if not qc_match:
        status = "ERROR"
    else:
        status = "PASS" if pe_match else "FAIL"
    detail = (
        f"[{theme}] expected color-overlay {tok}; quick_connect gutter samples {qc_samples} "
        f"-> {'matches (opaque card, correct)' if qc_match else 'NO MATCH (unexpected)'}; "
        f"profile_editor gutter samples {pe_samples} "
        f"-> {'matches (unexpected -- would mean the bug is fixed)' if pe_match else 'NO MATCH (bleed-through -- P7.2 defect #1)'}"
    )
    return CheckResult(
        "dialog_opacity_bleedthrough",
        status,
        detail,
        {"quick_connect": qc_samples, "profile_editor": pe_samples, "token": tok},
    )


def check_label_contrast(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """WCAG-style contrast between the dialogs' fixed label color
    (Theme.color-text-secondary, same token in both dialogs -- FormField/
    QuickConnectForm's own label Text) and the actual local background
    sampled at the same gutter points as the opacity check (a proxy for "the
    background right behind/near a label" since the harness has no
    glyph-level pixel readout). AA-normal-text threshold: 4.5."""
    fg = TOKENS[theme]["text_secondary"]

    qa.palette("Quick connect…")
    qa.dialog_set("quick_connect", "kind", 1)
    qa.settle()
    px = qa.pixel(GUTTER_POINTS)
    qc_bg = next((v for v in (_sample_rgb(px, r["name"]) for r in GUTTER_POINTS) if v), None)
    qa.dialog_click("quick_connect", "cancel")

    qa.palette("New RDP connection")
    qa.settle()
    px2 = qa.pixel(GUTTER_POINTS)
    pe_bg = next((v for v in (_sample_rgb(px2, r["name"]) for r in GUTTER_POINTS) if v), None)
    qa.dialog_click("profile_editor", "cancel")

    qc_ratio = contrast_ratio(fg, qc_bg) if qc_bg else None
    pe_ratio = contrast_ratio(fg, pe_bg) if pe_bg else None
    qc_ok = qc_ratio is not None and qc_ratio >= 4.5
    pe_ok = pe_ratio is not None and pe_ratio >= 4.5
    qc_ratio_s = f"{qc_ratio:.2f}" if qc_ratio is not None else "n/a"
    pe_ratio_s = f"{pe_ratio:.2f}" if pe_ratio is not None else "n/a"

    # Status tracks profile_editor; quick_connect is the positive control --
    # see check_field_manifest_rdp_port_default's comment for the rationale.
    if not qc_ok:
        status = "ERROR"
    else:
        status = "PASS" if pe_ok else "FAIL"
    detail = (
        f"[{theme}] label fg={fg} (Theme.color-text-secondary); "
        f"quick_connect local bg={qc_bg} ratio={qc_ratio_s} ({'OK' if qc_ok else 'LOW'}); "
        f"profile_editor local bg={pe_bg} ratio={pe_ratio_s} ({'OK' if pe_ok else 'LOW -- P7.2 defect #1 (legibility)'}). "
        "NOTE: this samples a nearby gutter pixel as a proxy for the background directly "
        "behind a label glyph, not the exact glyph-local pixel (the harness has no "
        "glyph-position readout) -- treat as approximate, especially where it disagrees "
        "with a direct visual read."
    )
    return CheckResult(
        "label_contrast",
        status,
        detail,
        {"quick_connect_ratio": qc_ratio, "profile_editor_ratio": pe_ratio},
    )


def check_controls_not_clipped(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """P7.2 defect #2 (part 3): the profile editor's field list has no
    scroll region, so on a short window Save/Cancel can clip below the fold.
    The harness has no live window-resize command (out of this wave's
    scope), so this is a structural check (grep profile_editor.slint for a
    ScrollView/Flickable wrapping the form) plus an informational live
    margin measurement at the suite's actual window size."""
    src = (REPO_ROOT / "crates/cm-ui/ui/screens/profile_editor.slint").read_text()
    # Isolate the ProfileEditor component body (up to the GroupEditor that follows).
    m = re.search(r"export component ProfileEditor \{(.*?)\nexport component GroupEditor", src, re.S)
    body = m.group(1) if m else src
    has_scroll = bool(re.search(r"\b(ScrollView|Flickable)\b", body))

    qa.palette("New SSH connection")
    qa.settle()
    st = qa.state()
    shot = out_dir / f"controls-clip-{theme}.png"
    ss = qa.screenshot(str(shot))
    qa.dialog_click("profile_editor", "cancel")

    status = "PASS" if has_scroll else "FAIL"
    detail = (
        f"profile_editor.slint's ProfileEditor component "
        f"{'HAS' if has_scroll else 'has NO'} a ScrollView/Flickable around its field list "
        f"-- {'a short window keeps Save/Cancel reachable' if has_scroll else 'on a short window Save/Cancel can clip below the fold (P7.2 defect #2)'}. "
        f"Informational only: at this run's window size ({ss.get('width')}x{ss.get('height')}), "
        "no live clip is expected (the structural absence-of-scroll finding is the "
        "resolution-independent signal for this defect)."
    )
    return CheckResult("controls_not_clipped", status, detail, {"has_scroll_view": has_scroll})


def check_tab_sidebar_geometry(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """P7.3 defect #5: first tab's left inset should be a deliberate value
    (not flush to the corner) and there should be a visible divider/gap
    between the tab strip and the sidebar below it."""
    qa.settle()
    shot = out_dir / f"geometry-{theme}.png"
    qa.screenshot(str(shot))

    # Inset: compare the very corner (x=0) against clearly-inside-the-tab
    # (x=50) at tab-row mid-height. A flush tab (inset ~0) means both samples
    # match; a deliberate inset would show the OUTER chrome/background color
    # at x=0 before the tab card begins.
    inset_px = qa.pixel(
        [
            {"name": "corner", "x": 0, "y": 15, "w": 2, "h": 2},
            {"name": "tab_mid", "x": 50, "y": 15, "w": 2, "h": 2},
        ]
    )
    corner = _sample_rgb(inset_px, "corner")
    tab_mid = _sample_rgb(inset_px, "tab_mid")
    flush = corner is not None and tab_mid is not None and _color_dist(corner, tab_mid) <= MATCH_TOLERANCE

    # Divider: scan a column just below the tab strip / above the sidebar for
    # a distinct hairline color between the two flat bands. Sampled outside
    # any tab card (x=150) so it reads the tab-strip's own background.
    boundary_regions = [
        {"name": f"y{y}", "x": 150, "y": y, "w": 6, "h": 1} for y in range(24, 45)
    ]
    boundary_px = qa.pixel(boundary_regions)
    samples = {int(k[1:]): _sample_rgb(boundary_px, k) for k in (r["name"] for r in boundary_regions)}
    colors_seen = {c for c in samples.values() if c is not None}
    # A real divider would show a THIRD distinct color between the two flat
    # bands (tab-strip bg -> divider -> sidebar bg); a flush cut only ever
    # shows two.
    has_divider = len(colors_seen) >= 3
    inset_present = not flush

    # Spec wording pins two independent, ANDed assertions: "first tab's left
    # inset (> 0)" and "a divider/gap between the tab-strip bottom and the
    # sidebar top". Either one failing is a FAIL for this check (matches
    # P7.3 defect #5, which is driven primarily by the missing divider —
    # the measured inset is small (a few px) but technically non-zero).
    status = "PASS" if (inset_present and has_divider) else "FAIL"
    detail = (
        f"[{theme}] first-tab corner={corner} vs mid-tab={tab_mid} -> "
        f"{'inset present (but only a few px -- perceptually near-flush)' if inset_present else 'FLUSH (~0px inset)'}; "
        f"tab-strip/sidebar boundary column shows {len(colors_seen)} distinct color(s) "
        f"({'no divider -- P7.3 defect #5' if not has_divider else 'a divider band is present'})"
    )
    return CheckResult(
        "tab_sidebar_geometry",
        status,
        detail,
        {"corner": corner, "tab_mid": tab_mid, "boundary_colors": list(colors_seen)},
    )


def check_chrome_reachable_and_cancel(qa: QaClient, out_dir: Path, theme: str) -> CheckResult:
    """P7.2/P7.5 defect #4: with a connecting overlay open (slow-host
    fixture: a TCP-blackholed test-net address that never answers, so the
    attempt sits in "connecting" for a long time -- no live infra needed),
    the tab strip/sidebar/status pill must stay hit-testable, and the
    connecting overlay should expose a Cancel affordance.

    Chrome reachability is asserted live (Ctrl+Shift+<N> tab-jump, already
    routed through AppWindow::key-input regardless of dialog/overlay state --
    see sessions.rs's classify_ctrl_shift_shortcut -- works whether or not a
    tab is mid-connect). The Cancel affordance is asserted structurally
    (session_overlays.slint's ConnectingOverlay has no cancel callback at
    all -- there is nothing for a click to reach), since the harness's
    dialog_click registry intentionally does not cover session overlays
    (only the seven modal dialogs named in the P7.4 spec) and pixel-hunting
    for the ABSENCE of a button across arbitrary coordinates is not a
    reliable technique.
    """
    before = qa.state()
    n_tabs_before = len(before["state"]["tabs"])

    qa.palette("Quick connect…")
    qa.dialog_set("quick_connect", "kind", 0)
    qa.dialog_set("quick_connect", "host", "192.0.2.1")  # TEST-NET-1: blackholed, never responds
    qa.dialog_set("quick_connect", "port", "22")
    qa.dialog_set("quick_connect", "username", "qa-suite-probe")
    qa.dialog_set("quick_connect", "auth_method", 1)
    qa.dialog_set("quick_connect", "secret", "x")
    qa.dialog_click("quick_connect", "connect")

    st = qa.state()
    tabs = st["state"]["tabs"]
    connecting_idx = next((i for i, t in enumerate(tabs) if t["status"] == "connecting"), None)
    if connecting_idx is None or len(tabs) <= n_tabs_before:
        return CheckResult(
            "chrome_reachable_and_cancel",
            "SKIP",
            f"slow-host fixture did not produce a connecting tab in time: {st}",
        )

    qa.settle()
    shot = out_dir / f"chrome-reachable-{theme}.png"
    qa.screenshot(str(shot))

    # Reachability: jump to tab 1, confirm active flips; jump back to the
    # connecting tab, confirm it flips back -- proves tab-switching (a core
    # chrome affordance) is not blocked by the overlay.
    other_idx = 0 if connecting_idx != 0 else 1
    qa.key(text=str(other_idx + 1), modifiers=["ctrl", "shift"])
    mid = qa.state()
    switched_away = mid["state"]["tabs"][other_idx]["active"]
    qa.key(text=str(connecting_idx + 1), modifiers=["ctrl", "shift"])
    back = qa.state()
    switched_back = back["state"]["tabs"][connecting_idx]["active"]
    reachable = switched_away and switched_back

    # Cancel affordance: structural check on the ConnectingOverlay component.
    src = (REPO_ROOT / "crates/cm-ui/ui/screens/session_overlays.slint").read_text()
    m = re.search(r"export component ConnectingOverlay inherits Rectangle \{(.*?)\n\}\n", src, re.S)
    body = m.group(1) if m else ""
    has_cancel = bool(re.search(r"callback\s+cancel\s*\(", body)) or "\"Cancel\"" in body

    # Clean up: close the connecting tab so the suite leaves no stray tabs
    # (best-effort; the tab may still be within the OS TCP-connect timeout).
    qa.key(text="w", modifiers=["ctrl", "shift"])

    status = "PASS" if reachable and has_cancel else ("FAIL" if not reachable else "PARTIAL")
    detail = (
        f"[{theme}] chrome reachable under the connecting overlay: {reachable} "
        f"(tab-switch away={switched_away}, back={switched_back}); "
        f"ConnectingOverlay exposes a Cancel affordance: {has_cancel} "
        f"({'ok' if has_cancel else 'ABSENT -- the tab close (✕) is the only escape hatch during connect'})"
    )
    return CheckResult(
        "chrome_reachable_and_cancel",
        status,
        detail,
        {"reachable": reachable, "has_cancel": has_cancel, "screenshot": str(shot)},
    )


def check_live_rdp_smoke(qa: QaClient, out_dir: Path, theme: str, rdp_host: str | None, rdp_user: str | None, rdp_password: str | None) -> CheckResult:
    """Live-RDP smoke: quick-connect to an operator-supplied healthy TLS RDP
    target and assert the tab reaches Connected (not Failed) within a bound.
    Never hardcodes a host/credential (CONVENTIONS secrets hygiene + no host
    details in tracked files) -- skipped unless QA_RDP_HOST is set."""
    if not rdp_host:
        return CheckResult(
            "live_rdp_smoke",
            "SKIP",
            "QA_RDP_HOST not set -- no RDP target configured for this run. "
            "Set QA_RDP_HOST/QA_RDP_USER/QA_RDP_PASSWORD to exercise this check "
            "against a real target (see the rubric memo).",
        )

    qa.palette("Quick connect…")
    qa.dialog_set("quick_connect", "kind", 1)
    qa.dialog_set("quick_connect", "host", rdp_host)
    qa.dialog_set("quick_connect", "port", "3389")
    qa.dialog_set("quick_connect", "username", rdp_user or "")
    qa.dialog_set("quick_connect", "secret", rdp_password or "")
    qa.dialog_click("quick_connect", "connect")

    deadline = time.time() + 20.0
    last_status = None
    while time.time() < deadline:
        st = qa.state()
        tabs = st["state"]["tabs"]
        if tabs:
            last_status = tabs[-1]["status"]
            if last_status in ("connected", "failed"):
                break
        time.sleep(0.5)

    qa.settle()
    shot = out_dir / f"live-rdp-smoke-{theme}.png"
    qa.screenshot(str(shot))

    ok = last_status == "connected"
    status = "PASS" if ok else "FAIL"
    detail = f"RDP quick-connect to {rdp_host} reached status={last_status!r} within 20s (expect 'connected')"
    return CheckResult("live_rdp_smoke", status, detail, {"final_status": last_status, "screenshot": str(shot)})


CHECKS: list[Callable[..., CheckResult]] = [
    check_dialog_enabler_demo,
    check_field_manifest_rdp_port_default,
    check_field_manifest_rdp_domain_resolution,
    check_dialog_opacity_bleedthrough,
    check_label_contrast,
    check_controls_not_clipped,
    check_tab_sidebar_geometry,
    check_chrome_reachable_and_cancel,
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--theme", choices=["light", "dark"], required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--json-out", default=None, help="write the full JSON report here too")
    ap.add_argument("--rdp-host", default=None, help="or set QA_RDP_HOST")
    ap.add_argument("--rdp-user", default=None, help="or set QA_RDP_USER")
    ap.add_argument("--rdp-password", default=None, help="or set QA_RDP_PASSWORD")
    args = ap.parse_args()

    import os

    rdp_host = args.rdp_host or os.environ.get("QA_RDP_HOST")
    rdp_user = args.rdp_user or os.environ.get("QA_RDP_USER")
    rdp_password = args.rdp_password or os.environ.get("QA_RDP_PASSWORD")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    qa = QaClient(args.host, args.port, scratch_path=str(out_dir / "qa-visual-suite-settle.png"))
    results: list[CheckResult] = []
    try:
        for check in CHECKS:
            try:
                results.append(check(qa, out_dir, args.theme))
            except Exception as exc:  # noqa: BLE001 -- a check erroring is itself a result
                results.append(CheckResult(check.__name__, "ERROR", f"{type(exc).__name__}: {exc}"))
        results.append(check_live_rdp_smoke(qa, out_dir, args.theme, rdp_host, rdp_user, rdp_password))
    finally:
        try:
            qa.send({"cmd": "quit"})
        except Exception:
            pass
        qa.close()

    report = {
        "theme": args.theme,
        "port": args.port,
        "checks": [
            {"name": r.name, "status": r.status, "detail": r.detail, "evidence": r.evidence}
            for r in results
        ],
    }
    print(f"\n=== qa-visual-suite ({args.theme}) ===")
    for r in results:
        print(f"[{r.status:5}] {r.name}: {r.detail}")
    print()

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2))

    any_error = any(r.status == "ERROR" for r in results)
    return 1 if any_error else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ConnectionError) as exc:
        print(f"[qa-visual-suite] FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
