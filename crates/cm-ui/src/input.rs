//! Pure input mapping: Slint event payloads → `cm_core` terminal events and
//! transport-neutral RDP input events.
//!
//! These are free functions with no Slint or session dependency so they are unit-testable
//! headlessly (no window, no backend). The controller calls them and forwards the result to
//! the active session.
//!
//! Modifiers cross from `.slint` packed into a small bitmask (`MOD_*`) to keep the callback
//! arities low; [`mods_from_bits`] unpacks them.
//!
//! RDP input mappings:
//! - [`char_to_ps2_scancode`]: US keyboard layout scancode table (text → `(u8, bool)`)
//! - [`map_rdp_key_down`] / [`map_rdp_key_up`]: produce `RdpInputEvent` key sequences
//! - [`map_rdp_mouse`]: produce `RdpInputEvent` pointer sequences with coordinate mapping
//! - [`map_rdp_scroll`]: produce `RdpInputEvent` scroll sequence

use cm_core::terminal::{Key, KeyEvent, KeyModifiers, MouseAction, MouseButton, MouseEvent};
use cm_session::{RdpInputEvent, RdpMouseButton};

pub(crate) const MOD_CTRL: i32 = 1;
pub(crate) const MOD_ALT: i32 = 2;
pub(crate) const MOD_SHIFT: i32 = 4;
pub(crate) const MOD_META: i32 = 8;

const SPECIAL_MODIFIER_FIRST: i32 = 27;
const SPECIAL_MODIFIER_LAST: i32 = 34;

/// Whether `special` identifies a physical modifier key at the Slint
/// boundary. Terminal sessions consume these standalone events: the modifier
/// state is carried on the subsequent real key instead of encoding the
/// platform's private control-character token as terminal input.
#[must_use]
pub(crate) fn is_modifier_special(special: i32) -> bool {
    (SPECIAL_MODIFIER_FIRST..=SPECIAL_MODIFIER_LAST).contains(&special)
}

fn mods_from_bits(bits: i32) -> KeyModifiers {
    KeyModifiers {
        ctrl: bits & MOD_CTRL != 0,
        alt: bits & MOD_ALT != 0,
        shift: bits & MOD_SHIFT != 0,
        sup: bits & MOD_META != 0,
    }
}

/// Map a Slint key event into zero or more `cm_core` key events.
///
/// `special` is the discriminant computed in `.slint` against the `Key.*` namespace
/// (0 = "use `text`"); see `ui/app.slint`. Printable input arrives in `text` (one
/// `KeyEvent` per scalar). The engine's `encode_key` performs the ctrl translation, so we
/// pass `Key::Char(base)` + the ctrl modifier rather than a precomposed control byte.
#[must_use]
pub(crate) fn map_key(text: &str, special: i32, mods_bits: i32) -> Vec<KeyEvent> {
    let mods = mods_from_bits(mods_bits);

    if is_modifier_special(special) {
        return Vec::new();
    }

    if special != 0 {
        let key = match special {
            1 => Key::Enter,
            2 => Key::Tab,
            3 => Key::Backspace,
            4 => Key::Escape,
            5 => Key::Up,
            6 => Key::Down,
            7 => Key::Left,
            8 => Key::Right,
            9 => Key::Home,
            10 => Key::End,
            11 => Key::PageUp,
            12 => Key::PageDown,
            13 => Key::Insert,
            14 => Key::Delete,
            101..=112 => Key::F((special - 100) as u8),
            _ => return Vec::new(),
        };
        return vec![KeyEvent { key, mods }];
    }

    text.chars()
        .filter_map(|c| {
            // Some platforms deliver the precomposed control char (e.g. Ctrl-C as U+0003)
            // in `text`; recover the base letter so `encode_key` can do the translation.
            let c = if mods.ctrl && ('\u{1}'..='\u{1a}').contains(&c) {
                char::from(b'a' + (c as u8 - 1))
            } else {
                c
            };
            // Drop stray control scalars that aren't a deliberate ctrl combo.
            if c.is_control() && !mods.ctrl {
                return None;
            }
            Some(KeyEvent {
                key: Key::Char(c),
                mods,
            })
        })
        .collect()
}

/// Map a Slint pointer event (button + kind + resolved cell) into a `MouseEvent`.
/// Returns `None` for buttons/kinds we don't forward.
#[must_use]
pub(crate) fn map_mouse(
    button: i32,
    kind: i32,
    row: u16,
    col: u16,
    mods_bits: i32,
) -> Option<MouseEvent> {
    let button = match button {
        1 => MouseButton::Left,
        2 => MouseButton::Right,
        3 => MouseButton::Middle,
        _ => return None,
    };
    let action = match kind {
        1 => MouseAction::Press,
        2 => MouseAction::Release,
        3 => MouseAction::Move,
        _ => return None,
    };
    Some(MouseEvent {
        button,
        action,
        row,
        col,
        mods: mods_from_bits(mods_bits),
    })
}

/// Map a vertical scroll delta (logical px) into a wheel `MouseEvent` at the given cell.
/// `delta_y > 0` scrolls the content up (wheel away from the user). Returns `None` for a
/// zero delta.
#[must_use]
pub(crate) fn map_scroll(delta_y: f32, row: u16, col: u16, mods_bits: i32) -> Option<MouseEvent> {
    if delta_y == 0.0 {
        return None;
    }
    let button = if delta_y > 0.0 {
        MouseButton::ScrollUp
    } else {
        MouseButton::ScrollDown
    };
    Some(MouseEvent {
        button,
        action: MouseAction::Press,
        row,
        col,
        mods: mods_from_bits(mods_bits),
    })
}

// ── PS/2 scancode table (US layout) ─────────────────────────────────────────

/// Return the PS/2 scancode and extended flag for a printable character or
/// special key delivered by the Slint FocusScope.
///
/// `text` is the UTF-8 string from `e.text`; `special` is the numeric
/// discriminant produced in `.slint` (see `RdpSurface`). Returns `None` for
/// characters not in the US-keyboard layout (accented, CJK, emoji, …) or for
/// modifier keys alone.
///
/// Extended flag (`true`) means the scancode requires an E0 prefix in the
/// RDP Fast-Path PDU; `ironrdp-input` handles that translation from a
/// `Scancode { code, extended }` pair.
#[must_use]
pub(crate) fn char_to_ps2_scancode(text: &str, special: i32) -> Option<(u8, bool)> {
    // ── Special keys (special != 0) ──────────────────────────────────────────
    if special != 0 {
        return match special {
            1 => Some((0x1C, false)),  // Enter (Return)
            2 => Some((0x0F, false)),  // Tab
            3 => Some((0x0E, false)),  // Backspace
            4 => Some((0x01, false)),  // Escape
            5 => Some((0x48, true)),   // Up arrow
            6 => Some((0x50, true)),   // Down arrow
            7 => Some((0x4B, true)),   // Left arrow
            8 => Some((0x4D, true)),   // Right arrow
            9 => Some((0x47, true)),   // Home
            10 => Some((0x4F, true)),  // End
            11 => Some((0x49, true)),  // Page Up
            12 => Some((0x51, true)),  // Page Down
            14 => Some((0x53, true)),  // Delete
            15 => Some((0x3B, false)), // F1
            16 => Some((0x3C, false)), // F2
            17 => Some((0x3D, false)), // F3
            18 => Some((0x3E, false)), // F4
            19 => Some((0x3F, false)), // F5
            20 => Some((0x40, false)), // F6
            21 => Some((0x41, false)), // F7
            22 => Some((0x42, false)), // F8
            23 => Some((0x43, false)), // F9
            24 => Some((0x44, false)), // F10
            25 => Some((0x57, false)), // F11
            26 => Some((0x58, false)), // F12
            _ => None,
        };
    }

    // ── Printable keys (US QWERTY layout) ───────────────────────────────────
    // Characters that require the Shift key on a US keyboard share the same
    // scancode as their unshifted counterpart; the caller sends a Shift modifier
    // down/up around the character scancode.
    let ch = text.chars().next()?;
    match ch {
        // Alpha (same scancode, upper or lower)
        'a' | 'A' => Some((0x1E, false)),
        'b' | 'B' => Some((0x30, false)),
        'c' | 'C' => Some((0x2E, false)),
        'd' | 'D' => Some((0x20, false)),
        'e' | 'E' => Some((0x12, false)),
        'f' | 'F' => Some((0x21, false)),
        'g' | 'G' => Some((0x22, false)),
        'h' | 'H' => Some((0x23, false)),
        'i' | 'I' => Some((0x17, false)),
        'j' | 'J' => Some((0x24, false)),
        'k' | 'K' => Some((0x25, false)),
        'l' | 'L' => Some((0x26, false)),
        'm' | 'M' => Some((0x32, false)),
        'n' | 'N' => Some((0x31, false)),
        'o' | 'O' => Some((0x18, false)),
        'p' | 'P' => Some((0x19, false)),
        'q' | 'Q' => Some((0x10, false)),
        'r' | 'R' => Some((0x13, false)),
        's' | 'S' => Some((0x1F, false)),
        't' | 'T' => Some((0x14, false)),
        'u' | 'U' => Some((0x16, false)),
        'v' | 'V' => Some((0x2F, false)),
        'w' | 'W' => Some((0x11, false)),
        'x' | 'X' => Some((0x2D, false)),
        'y' | 'Y' => Some((0x15, false)),
        'z' | 'Z' => Some((0x2C, false)),
        // Digits and shifted symbols (top row)
        '1' | '!' => Some((0x02, false)),
        '2' | '@' => Some((0x03, false)),
        '3' | '#' => Some((0x04, false)),
        '4' | '$' => Some((0x05, false)),
        '5' | '%' => Some((0x06, false)),
        '6' | '^' => Some((0x07, false)),
        '7' | '&' => Some((0x08, false)),
        '8' | '*' => Some((0x09, false)),
        '9' | '(' => Some((0x0A, false)),
        '0' | ')' => Some((0x0B, false)),
        '-' | '_' => Some((0x0C, false)),
        '=' | '+' => Some((0x0D, false)),
        // Square brackets / braces
        '[' | '{' => Some((0x1A, false)),
        ']' | '}' => Some((0x1B, false)),
        // Backslash / pipe
        '\\' | '|' => Some((0x2B, false)),
        // Semicolon / colon
        ';' | ':' => Some((0x27, false)),
        // Quote / double-quote
        '\'' | '"' => Some((0x28, false)),
        // Backtick / tilde
        '`' | '~' => Some((0x29, false)),
        // Comma / less-than
        ',' | '<' => Some((0x33, false)),
        // Period / greater-than
        '.' | '>' => Some((0x34, false)),
        // Slash / question mark
        '/' | '?' => Some((0x35, false)),
        // Space
        ' ' => Some((0x39, false)),
        _ => None,
    }
}

/// PS/2 scancodes for modifier key variants.
const SC_LCTRL: u8 = 0x1D;
const SC_LSHIFT: u8 = 0x2A;
const SC_LALT: u8 = 0x38;
const SC_RSHIFT: u8 = 0x36;
const SC_LMETA: u8 = 0x5B;
const SC_RMETA: u8 = 0x5C;
const SC_TAB: u8 = 0x0F;
const SC_DELETE: u8 = 0x53;

/// Resolve the modifier-specific `special` values emitted by `RdpSurface`.
///
/// Slint represents these keys with U+0010..U+0018 strings. Those values
/// overlap the ASCII control-character range, so they must be classified in
/// Slint before entering the printable-character path.
fn rdp_modifier_scancode(special: i32) -> Option<(u8, bool)> {
    match special {
        27 => Some((SC_LSHIFT, false)),
        28 => Some((SC_RSHIFT, false)),
        29 => Some((SC_LCTRL, false)),
        30 => Some((SC_LCTRL, true)),
        31 => Some((SC_LALT, false)),
        32 => Some((SC_LALT, true)),
        33 => Some((SC_LMETA, true)),
        34 => Some((SC_RMETA, true)),
        _ => None,
    }
}

/// Produce the RDP input sequence for a **key-down** event.
///
/// Physical modifiers arrive as their own callbacks and are forwarded exactly
/// once. Replaying modifier bits from every non-modifier event is incorrect:
/// `ironrdp_input::Database` deliberately encodes a repeated key-down as a
/// release followed by another press, which can break the chord being entered.
///
/// Ctrl+Alt+End is intercepted here as the conventional RDP client shortcut for
/// Ctrl+Alt+Delete. The explicit Session Action uses the same wire-level Delete
/// key, but supplies its own balanced modifier events.
#[must_use]
pub(crate) fn map_rdp_key_down(text: &str, special: i32, mods_bits: i32) -> Vec<RdpInputEvent> {
    if let Some((scancode, extended)) = rdp_modifier_scancode(special) {
        return vec![RdpInputEvent::KeyDown { scancode, extended }];
    }

    let (scancode, extended) =
        if special == 10 && mods_bits & (MOD_CTRL | MOD_ALT) == (MOD_CTRL | MOD_ALT) {
            (SC_DELETE, true)
        } else if let Some(key) = char_to_ps2_scancode(text, special) {
            key
        } else {
            return Vec::new();
        };

    vec![RdpInputEvent::KeyDown { scancode, extended }]
}

/// Produce the RDP `FastPathInputEvent` sequence for a **key-up** event.
///
/// A physical modifier event produces only that modifier's exact key-up,
/// including right-side/extended identity. Non-modifier keys do not release
/// modifiers: physical modifiers have their own key-up callbacks, while focus
/// loss uses [`rdp_release_all_modifiers_sequence`] as the recovery boundary.
///
/// End releases both End and Delete. The stateful IronRDP database drops the
/// release for whichever key is not down, making Ctrl+Alt+End interception
/// robust even when the modifier snapshot has changed by key-up time.
#[must_use]
pub(crate) fn map_rdp_key_up(text: &str, special: i32, _mods_bits: i32) -> Vec<RdpInputEvent> {
    if let Some((scancode, extended)) = rdp_modifier_scancode(special) {
        return vec![RdpInputEvent::KeyUp { scancode, extended }];
    }

    if special == 10 {
        return vec![key_up(0x4F, true), key_up(SC_DELETE, true)];
    }

    if let Some((sc, ext)) = char_to_ps2_scancode(text, special) {
        vec![RdpInputEvent::KeyUp {
            scancode: sc,
            extended: ext,
        }]
    } else {
        Vec::new()
    }
}

#[must_use]
pub(crate) fn rdp_modifier_key_ups() -> [RdpInputEvent; 8] {
    [
        RdpInputEvent::KeyUp {
            scancode: SC_LSHIFT,
            extended: false,
        },
        RdpInputEvent::KeyUp {
            scancode: SC_RSHIFT,
            extended: false,
        },
        RdpInputEvent::KeyUp {
            scancode: SC_LALT,
            extended: false,
        },
        RdpInputEvent::KeyUp {
            scancode: SC_LALT,
            extended: true,
        },
        RdpInputEvent::KeyUp {
            scancode: SC_LCTRL,
            extended: false,
        },
        RdpInputEvent::KeyUp {
            scancode: SC_LCTRL,
            extended: true,
        },
        RdpInputEvent::KeyUp {
            scancode: SC_LMETA,
            extended: true,
        },
        RdpInputEvent::KeyUp {
            scancode: SC_RMETA,
            extended: true,
        },
    ]
}

/// Build the RDP key sequence for the user-facing "Send Ctrl+Alt+Delete" action.
///
/// Ctrl+Alt+End is a host-side shortcut that clients such as mstsc intercept to
/// synthesize Ctrl+Alt+Delete. This action is already that client-side synthesis
/// boundary, so the RDP wire input must contain extended Delete itself. Every
/// key-down is paired with a reverse-order key-up so an interrupted host-side
/// modifier snapshot cannot leave either synthetic modifier pressed.
#[must_use]
pub(crate) fn rdp_ctrl_alt_delete_sequence() -> Vec<RdpInputEvent> {
    vec![
        key_down(SC_LCTRL, false),
        key_down(SC_LALT, false),
        key_down(SC_DELETE, true),
        key_up(SC_DELETE, true),
        key_up(SC_LALT, false),
        key_up(SC_LCTRL, false),
    ]
}

/// Build a momentary left Windows/Super key press for an RDP destination.
#[must_use]
pub(crate) fn rdp_windows_key_sequence() -> Vec<RdpInputEvent> {
    vec![key_down(SC_LMETA, true), key_up(SC_LMETA, true)]
}

/// Build a balanced Alt+Tab sequence for an RDP destination.
#[must_use]
pub(crate) fn rdp_alt_tab_sequence() -> Vec<RdpInputEvent> {
    vec![
        key_down(SC_LALT, false),
        key_down(SC_TAB, false),
        key_up(SC_TAB, false),
        key_up(SC_LALT, false),
    ]
}

/// Build the emergency release sequence for every modifier variant ConMan can
/// send to an RDP destination.
#[must_use]
pub(crate) fn rdp_release_all_modifiers_sequence() -> Vec<RdpInputEvent> {
    rdp_modifier_key_ups().into()
}

const fn key_down(scancode: u8, extended: bool) -> RdpInputEvent {
    RdpInputEvent::KeyDown { scancode, extended }
}

const fn key_up(scancode: u8, extended: bool) -> RdpInputEvent {
    RdpInputEvent::KeyUp { scancode, extended }
}

/// Coordinate-mapping context for RDP pointer events.
///
/// Groups the surface pixel size and RDP desktop resolution to keep mouse/scroll
/// functions below the `too_many_arguments` threshold.
pub(crate) struct RdpCoords {
    /// Logical-pixel width of the Slint surface area.
    pub surface_w: f32,
    /// Logical-pixel height of the Slint surface area.
    pub surface_h: f32,
    /// RDP desktop width in pixels.
    pub rdp_w: u16,
    /// RDP desktop height in pixels.
    pub rdp_h: u16,
}

impl RdpCoords {
    /// Map a logical surface position to an RDP pixel position.
    ///
    /// Returns `None` when the surface or desktop dimensions are zero.
    fn map(&self, x: f32, y: f32) -> Option<(u16, u16)> {
        if self.surface_w <= 0.0 || self.surface_h <= 0.0 || self.rdp_w == 0 || self.rdp_h == 0 {
            return None;
        }
        let rx =
            (x / self.surface_w * self.rdp_w as f32).clamp(0.0, self.rdp_w as f32 - 1.0) as u16;
        let ry =
            (y / self.surface_h * self.rdp_h as f32).clamp(0.0, self.rdp_h as f32 - 1.0) as u16;
        Some((rx, ry))
    }
}

/// Map a pointer event from the RDP surface into `RdpInputEvent`s.
///
/// Coordinates are in logical pixels relative to the Slint surface; they are
/// scaled to the RDP desktop resolution via [`RdpCoords`].
///
/// `button`: 1=left, 2=right, 3=middle, 0=none (move).
/// `kind`: 1=down, 2=up, 3=move.
#[must_use]
pub(crate) fn map_rdp_mouse(
    button: i32,
    kind: i32,
    x: f32,
    y: f32,
    coords: &RdpCoords,
) -> Vec<RdpInputEvent> {
    let Some((rdp_x, rdp_y)) = coords.map(x, y) else {
        return Vec::new();
    };
    let btn = match button {
        1 => Some(RdpMouseButton::Left),
        2 => Some(RdpMouseButton::Right),
        3 => Some(RdpMouseButton::Middle),
        _ => None,
    };
    let mut events = Vec::with_capacity(2);
    // Always emit a move so the cursor tracks the pointer.
    events.push(RdpInputEvent::MouseMove { x: rdp_x, y: rdp_y });
    match (btn, kind) {
        (Some(b), 1) => events.push(RdpInputEvent::MouseDown {
            button: b,
            x: rdp_x,
            y: rdp_y,
        }),
        (Some(b), 2) => events.push(RdpInputEvent::MouseUp {
            button: b,
            x: rdp_x,
            y: rdp_y,
        }),
        _ => {}
    }
    events
}

/// Map a scroll-wheel delta from the RDP surface into `RdpInputEvent`s.
///
/// `dy > 0` = scroll up (wheel away from user); `dy < 0` = scroll down.
/// Coordinates are mapped via [`RdpCoords`].
#[must_use]
pub(crate) fn map_rdp_scroll(dy: f32, x: f32, y: f32, coords: &RdpCoords) -> Vec<RdpInputEvent> {
    let Some((rdp_x, rdp_y)) = coords.map(x, y) else {
        return Vec::new();
    };
    if dy == 0.0 {
        return Vec::new();
    }
    // Convert Slint logical-pixel delta to RDP wheel units (120 = one standard step).
    // Slint typically delivers 3–15 logical pixels per wheel step; multiply to get ~120.
    let delta = (dy * 12.0).clamp(-3600.0, 3600.0) as i16;
    vec![RdpInputEvent::Scroll {
        delta,
        vertical: true,
        x: rdp_x,
        y: rdp_y,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum TestKeyEvent {
        Down(u8, bool),
        Up(u8, bool),
    }

    fn key_events(events: &[RdpInputEvent]) -> Vec<TestKeyEvent> {
        events
            .iter()
            .map(|event| match event {
                RdpInputEvent::KeyDown { scancode, extended } => {
                    TestKeyEvent::Down(*scancode, *extended)
                }
                RdpInputEvent::KeyUp { scancode, extended } => {
                    TestKeyEvent::Up(*scancode, *extended)
                }
                _ => panic!("expected an RDP keyboard event"),
            })
            .collect()
    }

    #[test]
    fn printable_text_maps_to_char() {
        let evs = map_key("a", 0, 0);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].key, Key::Char('a'));
        assert!(!evs[0].mods.ctrl);
    }

    #[test]
    fn special_enter_and_arrows() {
        assert_eq!(map_key("", 1, 0)[0].key, Key::Enter);
        assert_eq!(map_key("", 5, 0)[0].key, Key::Up);
        assert_eq!(map_key("", 14, 0)[0].key, Key::Delete);
    }

    #[test]
    fn function_keys() {
        assert_eq!(map_key("", 101, 0)[0].key, Key::F(1));
        assert_eq!(map_key("", 112, 0)[0].key, Key::F(12));
    }

    #[test]
    fn standalone_terminal_modifiers_are_dropped() {
        let windows_tokens = [
            "\u{f}", "\u{10}", "\u{11}", "\u{16}", "\u{12}", "\u{13}", "\u{14}", "\u{15}",
        ];
        for (special, text) in (27..=34).zip(windows_tokens) {
            assert!(is_modifier_special(special));
            assert!(map_key(text, special, MOD_CTRL | MOD_SHIFT).is_empty());
        }
    }

    #[test]
    fn ctrl_letter_keeps_base_and_modifier() {
        // Base letter delivered in text.
        let evs = map_key("c", 0, MOD_CTRL);
        assert_eq!(evs[0].key, Key::Char('c'));
        assert!(evs[0].mods.ctrl);
        // Precomposed control char (U+0003) recovered to 'c'.
        let evs2 = map_key("\u{3}", 0, MOD_CTRL);
        assert_eq!(evs2[0].key, Key::Char('c'));
        assert!(evs2[0].mods.ctrl);
    }

    #[test]
    fn modifier_bits_unpack() {
        let evs = map_key("a", 0, MOD_CTRL | MOD_ALT | MOD_SHIFT | MOD_META);
        let m = evs[0].mods;
        assert!(m.ctrl && m.alt && m.shift && m.sup);
    }

    #[test]
    fn stray_control_char_without_ctrl_is_dropped() {
        assert!(map_key("\u{1b}", 0, 0).is_empty());
    }

    #[test]
    fn unknown_special_is_empty() {
        assert!(map_key("", 999, 0).is_empty());
    }

    #[test]
    fn mouse_button_and_kind() {
        let ev = map_mouse(1, 1, 3, 7, 0).unwrap();
        assert_eq!(ev.button, MouseButton::Left);
        assert_eq!(ev.action, MouseAction::Press);
        assert_eq!((ev.row, ev.col), (3, 7));
        assert!(map_mouse(0, 1, 0, 0, 0).is_none());
        assert!(map_mouse(1, 9, 0, 0, 0).is_none());
    }

    #[test]
    fn scroll_direction() {
        assert_eq!(
            map_scroll(5.0, 0, 0, 0).unwrap().button,
            MouseButton::ScrollUp
        );
        assert_eq!(
            map_scroll(-5.0, 0, 0, 0).unwrap().button,
            MouseButton::ScrollDown
        );
        assert!(map_scroll(0.0, 0, 0, 0).is_none());
    }

    #[test]
    fn rdp_slint_modifier_tokens_are_never_printable_characters() {
        for token in '\u{10}'..='\u{18}' {
            assert_eq!(
                char_to_ps2_scancode(&token.to_string(), 0),
                None,
                "Slint modifier token U+{:04X} must not become a letter",
                token as u32
            );
        }
    }

    #[test]
    fn rdp_nonmodifier_does_not_replay_or_release_modifier_snapshot() {
        assert_eq!(
            key_events(&map_rdp_key_down("c", 0, MOD_CTRL | MOD_SHIFT)),
            [TestKeyEvent::Down(0x2e, false)]
        );
        assert_eq!(
            key_events(&map_rdp_key_up("c", 0, MOD_CTRL | MOD_SHIFT)),
            [TestKeyEvent::Up(0x2e, false)]
        );
    }

    #[test]
    fn rdp_physical_ctrl_alt_end_intercepts_to_delete_without_modifier_churn() {
        let mut events = Vec::new();
        events.extend(map_rdp_key_down("", 29, MOD_CTRL));
        events.extend(map_rdp_key_down("", 31, MOD_CTRL | MOD_ALT));
        events.extend(map_rdp_key_down("", 10, MOD_CTRL | MOD_ALT));
        events.extend(map_rdp_key_up("", 10, MOD_CTRL | MOD_ALT));
        events.extend(map_rdp_key_up("", 31, MOD_CTRL));
        events.extend(map_rdp_key_up("", 29, 0));

        assert_eq!(
            key_events(&events),
            [
                TestKeyEvent::Down(SC_LCTRL, false),
                TestKeyEvent::Down(SC_LALT, false),
                TestKeyEvent::Down(SC_DELETE, true),
                // IronRDP drops this unmatched End release at the production
                // boundary and preserves the following Delete release.
                TestKeyEvent::Up(0x4f, true),
                TestKeyEvent::Up(SC_DELETE, true),
                TestKeyEvent::Up(SC_LALT, false),
                TestKeyEvent::Up(SC_LCTRL, false),
            ]
        );
    }

    #[test]
    fn rdp_ctrl_alt_delete_uses_balanced_extended_delete_wire_sequence() {
        assert_eq!(
            key_events(&rdp_ctrl_alt_delete_sequence()),
            [
                TestKeyEvent::Down(SC_LCTRL, false),
                TestKeyEvent::Down(SC_LALT, false),
                TestKeyEvent::Down(SC_DELETE, true),
                TestKeyEvent::Up(SC_DELETE, true),
                TestKeyEvent::Up(SC_LALT, false),
                TestKeyEvent::Up(SC_LCTRL, false),
            ]
        );
    }

    #[test]
    fn rdp_windows_key_is_momentary_and_extended() {
        assert_eq!(
            key_events(&rdp_windows_key_sequence()),
            [
                TestKeyEvent::Down(SC_LMETA, true),
                TestKeyEvent::Up(SC_LMETA, true),
            ]
        );
    }

    #[test]
    fn rdp_alt_tab_releases_tab_before_alt() {
        assert_eq!(
            key_events(&rdp_alt_tab_sequence()),
            [
                TestKeyEvent::Down(SC_LALT, false),
                TestKeyEvent::Down(SC_TAB, false),
                TestKeyEvent::Up(SC_TAB, false),
                TestKeyEvent::Up(SC_LALT, false),
            ]
        );
    }

    #[test]
    fn rdp_release_all_modifiers_covers_left_right_and_extended_variants() {
        assert_eq!(
            key_events(&rdp_release_all_modifiers_sequence()),
            [
                TestKeyEvent::Up(SC_LSHIFT, false),
                TestKeyEvent::Up(SC_RSHIFT, false),
                TestKeyEvent::Up(SC_LALT, false),
                TestKeyEvent::Up(SC_LALT, true),
                TestKeyEvent::Up(SC_LCTRL, false),
                TestKeyEvent::Up(SC_LCTRL, true),
                TestKeyEvent::Up(SC_LMETA, true),
                TestKeyEvent::Up(SC_RMETA, true),
            ]
        );
    }

    // ── RdpCoords::map ────────────────────────────────────────────────────────

    #[test]
    fn rdp_coords_map_scales_correctly() {
        let c = RdpCoords {
            surface_w: 1280.0,
            surface_h: 720.0,
            rdp_w: 1920,
            rdp_h: 1080,
        };
        // Centre of surface → centre of RDP desktop.
        let (rx, ry) = c.map(640.0, 360.0).unwrap();
        assert_eq!(rx, 960);
        assert_eq!(ry, 540);
    }

    #[test]
    fn rdp_coords_map_zero_surface_returns_none() {
        // Zero-dim surface → None.
        let c = RdpCoords {
            surface_w: 0.0,
            surface_h: 720.0,
            rdp_w: 1920,
            rdp_h: 1080,
        };
        assert!(c.map(0.0, 0.0).is_none());

        let c2 = RdpCoords {
            surface_w: 1280.0,
            surface_h: 0.0,
            rdp_w: 1920,
            rdp_h: 1080,
        };
        assert!(c2.map(0.0, 0.0).is_none());
    }

    #[test]
    fn rdp_coords_map_zero_rdp_returns_none() {
        let c = RdpCoords {
            surface_w: 1280.0,
            surface_h: 720.0,
            rdp_w: 0,
            rdp_h: 1080,
        };
        assert!(c.map(100.0, 100.0).is_none());
    }

    #[test]
    fn rdp_coords_map_clamps_to_rdp_bounds() {
        let c = RdpCoords {
            surface_w: 100.0,
            surface_h: 100.0,
            rdp_w: 200,
            rdp_h: 200,
        };
        // Coordinates beyond the surface edge should clamp to rdp_w/h - 1.
        let (rx, ry) = c.map(200.0, 200.0).unwrap();
        assert_eq!(rx, 199);
        assert_eq!(ry, 199);
        // Negative — clamps to 0.
        let (rx, ry) = c.map(-50.0, -50.0).unwrap();
        assert_eq!(rx, 0);
        assert_eq!(ry, 0);
    }

    // ── map_rdp_mouse ─────────────────────────────────────────────────────────

    #[test]
    fn map_rdp_mouse_left_down_emits_move_then_down() {
        let c = RdpCoords {
            surface_w: 100.0,
            surface_h: 100.0,
            rdp_w: 100,
            rdp_h: 100,
        };
        let evs = map_rdp_mouse(1, 1, 50.0, 50.0, &c);
        assert_eq!(evs.len(), 2);
        assert!(matches!(evs[0], RdpInputEvent::MouseMove { x: 50, y: 50 }));
        assert!(matches!(
            evs[1],
            RdpInputEvent::MouseDown {
                button: RdpMouseButton::Left,
                x: 50,
                y: 50
            }
        ));
    }

    #[test]
    fn map_rdp_mouse_move_only_emits_move() {
        let c = RdpCoords {
            surface_w: 100.0,
            surface_h: 100.0,
            rdp_w: 100,
            rdp_h: 100,
        };
        // button=0 (no button), kind=3 (move)
        let evs = map_rdp_mouse(0, 3, 25.0, 75.0, &c);
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], RdpInputEvent::MouseMove { .. }));
    }

    #[test]
    fn map_rdp_mouse_zero_dim_returns_empty() {
        let c = RdpCoords {
            surface_w: 0.0,
            surface_h: 100.0,
            rdp_w: 100,
            rdp_h: 100,
        };
        assert!(map_rdp_mouse(1, 1, 50.0, 50.0, &c).is_empty());
    }

    // ── map_rdp_scroll ────────────────────────────────────────────────────────

    #[test]
    fn map_rdp_scroll_positive_dy_is_vertical_positive_delta() {
        let c = RdpCoords {
            surface_w: 100.0,
            surface_h: 100.0,
            rdp_w: 100,
            rdp_h: 100,
        };
        let evs = map_rdp_scroll(10.0, 50.0, 50.0, &c);
        assert_eq!(evs.len(), 1);
        let RdpInputEvent::Scroll {
            delta,
            vertical,
            x,
            y,
        } = evs[0]
        else {
            panic!("expected Scroll event");
        };
        assert!(vertical);
        assert!(delta > 0, "positive dy should produce positive delta");
        assert_eq!(x, 50);
        assert_eq!(y, 50);
    }

    #[test]
    fn map_rdp_scroll_zero_dy_returns_empty() {
        let c = RdpCoords {
            surface_w: 100.0,
            surface_h: 100.0,
            rdp_w: 100,
            rdp_h: 100,
        };
        assert!(map_rdp_scroll(0.0, 50.0, 50.0, &c).is_empty());
    }

    #[test]
    fn map_rdp_scroll_zero_dim_returns_empty() {
        let c = RdpCoords {
            surface_w: 0.0,
            surface_h: 0.0,
            rdp_w: 100,
            rdp_h: 100,
        };
        assert!(map_rdp_scroll(5.0, 0.0, 0.0, &c).is_empty());
    }

    #[test]
    fn map_rdp_scroll_clamps_large_delta() {
        let c = RdpCoords {
            surface_w: 100.0,
            surface_h: 100.0,
            rdp_w: 100,
            rdp_h: 100,
        };
        // Very large dy should be clamped to ±3600.
        let evs = map_rdp_scroll(10000.0, 50.0, 50.0, &c);
        let RdpInputEvent::Scroll { delta, .. } = evs[0] else {
            panic!("expected Scroll event");
        };
        assert_eq!(delta, 3600, "large positive dy should clamp to 3600");

        let evs_neg = map_rdp_scroll(-10000.0, 50.0, 50.0, &c);
        let RdpInputEvent::Scroll {
            delta: delta_neg, ..
        } = evs_neg[0]
        else {
            panic!("expected Scroll event");
        };
        assert_eq!(delta_neg, -3600, "large negative dy should clamp to -3600");
    }
}
