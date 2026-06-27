//! Pure input mapping: Slint event payloads → `cm_core` terminal events.
//!
//! These are free functions with no Slint or session dependency so they are unit-testable
//! headlessly (no window, no backend). The controller calls them and forwards the result to
//! the active session.
//!
//! Modifiers cross from `.slint` packed into a small bitmask (`MOD_*`) to keep the callback
//! arities low; [`mods_from_bits`] unpacks them.

use cm_core::terminal::{Key, KeyEvent, KeyModifiers, MouseAction, MouseButton, MouseEvent};

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
