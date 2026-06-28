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
//! P4.2 additions:
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
/// discriminant produced in `.slint` (see `RdpSurface`).  Returns `None` for
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
            1  => Some((0x1C, false)), // Enter (Return)
            2  => Some((0x0F, false)), // Tab
            3  => Some((0x0E, false)), // Backspace
            4  => Some((0x01, false)), // Escape
            5  => Some((0x48, true)),  // Up arrow
            6  => Some((0x50, true)),  // Down arrow
            7  => Some((0x4B, true)),  // Left arrow
            8  => Some((0x4D, true)),  // Right arrow
            9  => Some((0x47, true)),  // Home
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
            _  => None,
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

/// PS/2 scancode for the left modifier key variants.
const SC_LCTRL:  u8 = 0x1D;
const SC_LSHIFT: u8 = 0x2A;
const SC_LALT:   u8 = 0x38;

/// Produce the RDP `FastPathInputEvent` sequence for a **key-down** event.
///
/// The returned vector contains, in order:
/// 1. Left Ctrl key-down (if `mods_bits & MOD_CTRL`).
/// 2. Left Alt key-down (if `mods_bits & MOD_ALT`).
/// 3. Left Shift key-down (if `mods_bits & MOD_SHIFT`).
/// 4. The character or special-key key-down (if the key has a US-layout scancode).
///
/// Modifiers that were already down on the server (e.g. from a previous event)
/// are harmlessly repeated by this approach; IronRDP's input database
/// coalesces duplicate modifier presses correctly.
#[must_use]
pub(crate) fn map_rdp_key_down(
    text: &str,
    special: i32,
    mods_bits: i32,
) -> Vec<RdpInputEvent> {
    let mut events = Vec::with_capacity(4);
    if mods_bits & MOD_CTRL != 0 {
        events.push(RdpInputEvent::KeyDown { scancode: SC_LCTRL, extended: false });
    }
    if mods_bits & MOD_ALT != 0 {
        events.push(RdpInputEvent::KeyDown { scancode: SC_LALT, extended: false });
    }
    if mods_bits & MOD_SHIFT != 0 {
        events.push(RdpInputEvent::KeyDown { scancode: SC_LSHIFT, extended: false });
    }
    if let Some((sc, ext)) = char_to_ps2_scancode(text, special) {
        events.push(RdpInputEvent::KeyDown { scancode: sc, extended: ext });
    }
    events
}

/// Produce the RDP `FastPathInputEvent` sequence for a **key-up** event.
///
/// The returned vector contains, in order:
/// 1. The character or special-key key-up.
/// 2. Left Shift key-up (if `mods_bits & MOD_SHIFT`).
/// 3. Left Alt key-up (if `mods_bits & MOD_ALT`).
/// 4. Left Ctrl key-up (if `mods_bits & MOD_CTRL`).
///
/// Note: modifier ups follow the character up (the reverse of key-down order).
#[must_use]
pub(crate) fn map_rdp_key_up(
    text: &str,
    special: i32,
    mods_bits: i32,
) -> Vec<RdpInputEvent> {
    let mut events = Vec::with_capacity(4);
    if let Some((sc, ext)) = char_to_ps2_scancode(text, special) {
        events.push(RdpInputEvent::KeyUp { scancode: sc, extended: ext });
    }
    if mods_bits & MOD_SHIFT != 0 {
        events.push(RdpInputEvent::KeyUp { scancode: SC_LSHIFT, extended: false });
    }
    if mods_bits & MOD_ALT != 0 {
        events.push(RdpInputEvent::KeyUp { scancode: SC_LALT, extended: false });
    }
    if mods_bits & MOD_CTRL != 0 {
        events.push(RdpInputEvent::KeyUp { scancode: SC_LCTRL, extended: false });
    }
    events
}

/// Map a pointer event from the RDP surface into `RdpInputEvent`s.
///
/// Coordinates are in logical pixels relative to the Slint surface; they are
/// scaled to the RDP desktop resolution (`rdp_w × rdp_h`).
///
/// `button`: 1=left, 2=right, 3=middle, 0=none (move).
/// `kind`:   1=down, 2=up, 3=move.
#[must_use]
pub(crate) fn map_rdp_mouse(
    button: i32,
    kind: i32,
    x: f32,
    y: f32,
    surface_w: f32,
    surface_h: f32,
    rdp_w: u16,
    rdp_h: u16,
) -> Vec<RdpInputEvent> {
    if surface_w <= 0.0 || surface_h <= 0.0 || rdp_w == 0 || rdp_h == 0 {
        return Vec::new();
    }
    let rdp_x = (x / surface_w * rdp_w as f32)
        .clamp(0.0, rdp_w as f32 - 1.0) as u16;
    let rdp_y = (y / surface_h * rdp_h as f32)
        .clamp(0.0, rdp_h as f32 - 1.0) as u16;

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
        (Some(b), 1) => events.push(RdpInputEvent::MouseDown { button: b, x: rdp_x, y: rdp_y }),
        (Some(b), 2) => events.push(RdpInputEvent::MouseUp   { button: b, x: rdp_x, y: rdp_y }),
        _ => {}
    }
    events
}

/// Map a scroll-wheel delta from the RDP surface into `RdpInputEvent`s.
///
/// `dy > 0` = scroll up (wheel away from user); `dy < 0` = scroll down.
/// Coordinates are mapped the same way as [`map_rdp_mouse`].
#[must_use]
pub(crate) fn map_rdp_scroll(
    dy: f32,
    x: f32,
    y: f32,
    surface_w: f32,
    surface_h: f32,
    rdp_w: u16,
    rdp_h: u16,
) -> Vec<RdpInputEvent> {
    if dy == 0.0 || surface_w <= 0.0 || surface_h <= 0.0 || rdp_w == 0 || rdp_h == 0 {
        return Vec::new();
    }
    let rdp_x = (x / surface_w * rdp_w as f32)
        .clamp(0.0, rdp_w as f32 - 1.0) as u16;
    let rdp_y = (y / surface_h * rdp_h as f32)
        .clamp(0.0, rdp_h as f32 - 1.0) as u16;
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
}
