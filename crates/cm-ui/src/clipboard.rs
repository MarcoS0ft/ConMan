//! Shared OS-clipboard helper (P6.5).
//!
//! The app links exactly one clipboard dependency (`arboard`, P4.2's
//! `docs/devel/memos/p4.2-clipboard-dep.md`). Before P6.5 its only call site was
//! the RDP CLIPRDR bidirectional sync (`controller::sessions`): a raw
//! `Option<arboard::Clipboard>` field on `State`. Terminal copy/paste (P6.5) needs
//! the exact same capability, so this module is now the **one** place that talks
//! to `arboard` — both RDP clipboard sync and terminal selection copy/paste go
//! through [`Clipboard`] rather than each holding/rebuilding their own handle.
//!
//! `arboard::Clipboard::new()` can fail (no display server, e.g. a bare Wayland
//! session without a clipboard protocol, or headless CI) — every method here
//! fails soft (returns `None` / `false`) rather than panicking, consistent with
//! CONVENTIONS §2 ("untrusted/absent I/O never aborts").
use std::fmt;

/// A lazily-usable handle to the OS clipboard. Constructing one never panics
/// even when no clipboard is available — every accessor just returns an
/// empty/failed result in that case, so callers do not need to special-case
/// "no display server" (headless CI, some Wayland compositors).
pub(crate) struct Clipboard(Option<arboard::Clipboard>);

impl Clipboard {
    /// Attempt to open the OS clipboard. `None` internally if it fails (e.g. no
    /// display) — every subsequent call then fails soft.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(arboard::Clipboard::new().ok())
    }

    /// Read the clipboard's current text, or `None` if unavailable / not text /
    /// the read failed.
    #[must_use]
    pub(crate) fn get_text(&mut self) -> Option<String> {
        self.0.as_mut().and_then(|c| c.get_text().ok())
    }

    /// Write `text` to the clipboard. Returns `true` on success, `false` if no
    /// clipboard is available or the write failed.
    pub(crate) fn set_text(&mut self, text: impl Into<String>) -> bool {
        self.0
            .as_mut()
            .is_some_and(|c| c.set_text(text.into()).is_ok())
    }
}

impl Default for Clipboard {
    fn default() -> Self {
        Self::new()
    }
}

// `arboard::Clipboard` has no useful `Debug`; expose a minimal one so `State`
// (which derives nothing but is inspected in a couple of `#[derive(Debug)]`-free
// contexts) can still be handled without a manual impl per struct.
impl fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clipboard")
            .field("available", &self.0.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_never_panics_regardless_of_display_availability() {
        // Headless CI commonly has no clipboard; construction must still succeed
        // (internally `None`) rather than panic.
        let _ = Clipboard::new();
    }

    #[test]
    fn unavailable_clipboard_fails_soft() {
        let mut cb = Clipboard(None);
        assert_eq!(cb.get_text(), None);
        assert!(!cb.set_text("hello"));
    }
}
