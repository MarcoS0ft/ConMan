//! OS accent-color read (P6.8, gap 10 — HANDOFF §3's one hard wiring item).
//!
//! Best-effort and infallible from the caller's point of view: [`os_accent`] always
//! returns a usable color, falling back to [`AccentColor::FALLBACK`] (the same
//! cool-blue the app has always defaulted to — `Theme.accent-presets[0]` /
//! `#3b82f6` in `cm-ui/ui/theme.slint`) whenever the platform has no accent concept,
//! the read fails, or nothing answers.
//!
//! Per OS:
//! - **Windows**: `DwmGetColorizationColor` (`dwmapi.dll`) — the same colorization
//!   value Windows itself uses to tint title bars/taskbar, and a reliable proxy for
//!   "the user's chosen accent" even when title-bar tinting is off. No live
//!   accent-change signal is wired yet (see [`watch_os_accent`]'s doc).
//! - **Linux**: best-effort via the `org.freedesktop.portal.Settings` desktop
//!   portal (`org.freedesktop.appearance` / `accent-color`), which GNOME and KDE
//!   implement. [`watch_os_accent`] additionally subscribes to the portal's
//!   `SettingChanged` signal for live updates while the app runs. No portal (most
//!   window managers, headless/CI) → fallback.
//! - **Everything else (macOS, …)**: fallback only (macOS is P6 gap 32, blocked on
//!   hardware — see `docs/devel/p6-gaps.md`).

/// An OS accent color, 0-255 per channel (no alpha — accent colors are opaque).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccentColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl AccentColor {
    /// The cool-blue fallback used whenever the real OS accent cannot be read.
    /// Matches `Theme.accent-presets[0]` (`#3b82f6`) so falling back is never a
    /// visually "wrong" color — just the same default ConMan has always shipped.
    pub const FALLBACK: AccentColor = AccentColor {
        r: 0x3b,
        g: 0x82,
        b: 0xf6,
    };
}

/// Reads the current OS accent color. Never fails — see the module docs for the
/// per-OS source and the fallback rule.
#[must_use]
pub fn os_accent() -> AccentColor {
    imp::read().unwrap_or(AccentColor::FALLBACK)
}

/// Best-effort live accent-change watch: spawns a background thread that invokes
/// `on_change` with the new color whenever the OS accent changes, for platforms
/// that expose such a signal.
///
/// Returns `true` if a watcher was actually started (currently: Linux, when a
/// portal answers), `false` otherwise — callers should treat `false` as "this
/// platform only supports a startup read via [`os_accent`]", not as an error.
pub fn watch_os_accent(on_change: impl Fn(AccentColor) + Send + 'static) -> bool {
    imp::watch(Box::new(on_change))
}

#[cfg(target_os = "linux")]
mod imp {
    use super::AccentColor;
    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::{OwnedValue, Structure, Value};

    const PORTAL_DEST: &str = "org.freedesktop.portal.Desktop";
    const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
    const PORTAL_IFACE: &str = "org.freedesktop.portal.Settings";
    const NAMESPACE: &str = "org.freedesktop.appearance";
    const KEY: &str = "accent-color";

    pub(super) fn read() -> Option<AccentColor> {
        let conn = Connection::session().ok()?;
        let proxy = Proxy::new(&conn, PORTAL_DEST, PORTAL_PATH, PORTAL_IFACE).ok()?;
        let value: OwnedValue = proxy.call("Read", &(NAMESPACE, KEY)).ok()?;
        decode_accent(value.into())
    }

    pub(super) fn watch(on_change: Box<dyn Fn(AccentColor) + Send + 'static>) -> bool {
        let spawned = std::thread::Builder::new()
            .name("cm-platform-accent-watch".to_owned())
            .spawn(move || watch_loop(&on_change));
        if let Err(e) = &spawned {
            tracing::warn!("accent: failed to spawn portal watch thread: {e}");
        }
        spawned.is_ok()
    }

    fn watch_loop(on_change: &(dyn Fn(AccentColor) + Send)) {
        let Ok(conn) = Connection::session() else {
            return;
        };
        let Ok(proxy) = Proxy::new(&conn, PORTAL_DEST, PORTAL_PATH, PORTAL_IFACE) else {
            return;
        };
        let Ok(signals) = proxy.receive_signal("SettingChanged") else {
            return;
        };
        for msg in signals {
            let Ok((namespace, key, value)) =
                msg.body().deserialize::<(String, String, OwnedValue)>()
            else {
                continue;
            };
            if namespace != NAMESPACE || key != KEY {
                continue;
            }
            if let Some(color) = decode_accent(value.into()) {
                on_change(color);
            }
        }
    }

    /// Decode a portal `accent-color` value: a `(ddd)` structure of RGB
    /// components in `0.0..=1.0`, per the `org.freedesktop.appearance` spec.
    /// Some portal implementations wrap the value in an extra variant layer
    /// (a long-standing quirk) — unwrap until a concrete type is reached.
    fn decode_accent(mut value: Value<'_>) -> Option<AccentColor> {
        const MAX_UNWRAP: u8 = 8; // defensive bound: never loop unboundedly on hostile/odd input.
        for _ in 0..MAX_UNWRAP {
            match value {
                Value::Value(inner) => value = *inner,
                _ => break,
            }
        }
        let s: Structure<'_> = value.try_into().ok()?;
        let fields = s.fields();
        if fields.len() != 3 {
            return None;
        }
        let r: f64 = fields[0].clone().try_into().ok()?;
        let g: f64 = fields[1].clone().try_into().ok()?;
        let b: f64 = fields[2].clone().try_into().ok()?;
        let to_u8 = |v: f64| (v.clamp(0.0, 1.0) * 255.0).round() as u8;
        Some(AccentColor {
            r: to_u8(r),
            g: to_u8(g),
            b: to_u8(b),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn structure_ddd(r: f64, g: f64, b: f64) -> Value<'static> {
            Value::Structure(Structure::from((r, g, b)))
        }

        #[test]
        fn decodes_a_plain_rgb_structure() {
            let v = structure_ddd(1.0, 0.5, 0.0);
            let c = decode_accent(v).expect("should decode");
            assert_eq!(
                c,
                AccentColor {
                    r: 255,
                    g: 128,
                    b: 0
                }
            );
        }

        #[test]
        fn unwraps_one_layer_of_double_variant_wrapping() {
            // The documented GNOME/KDE portal quirk: the reply value is itself
            // wrapped in an extra Value::Value(..) layer.
            let inner = structure_ddd(0.0, 1.0, 0.0);
            let wrapped = Value::Value(Box::new(inner));
            let c = decode_accent(wrapped).expect("should decode through one wrap");
            assert_eq!(c, AccentColor { r: 0, g: 255, b: 0 });
        }

        #[test]
        fn clamps_out_of_range_components() {
            // Hostile/malformed input must never panic or produce an invalid u8.
            let v = structure_ddd(-1.0, 2.0, 0.5);
            let c = decode_accent(v).expect("should still decode with clamping");
            assert_eq!(
                c,
                AccentColor {
                    r: 0,
                    g: 255,
                    b: 128
                }
            );
        }

        #[test]
        fn rejects_wrong_field_count() {
            let v = Value::Structure(Structure::from((1.0_f64, 0.0_f64)));
            assert!(decode_accent(v).is_none());
        }

        #[test]
        fn rejects_non_structure_value() {
            let v = Value::U32(42);
            assert!(decode_accent(v).is_none());
        }
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use super::AccentColor;

    /// Reads the DWM colorization color (`dwmapi.dll`'s `DwmGetColorizationColor`).
    ///
    /// **Compile- and runtime-UNVERIFIED in this task**: this agent's environment
    /// has only the `x86_64-unknown-linux-gnu` Rust target installed, so this
    /// `cfg`-gated module is never parsed by `cargo build`/`cargo check` here, and
    /// there is no Windows host to run it on. Written carefully against the
    /// vendored `windows` 0.62 crate source (`Win32::Graphics::Dwm`'s generated
    /// binding for `DwmGetColorizationColor`) — a Windows build/run is required to
    /// confirm it actually compiles and behaves as documented.
    pub(super) fn read() -> Option<AccentColor> {
        let mut color: u32 = 0;
        let mut opaque_blend = windows::core::BOOL(0);
        // SAFETY: both out-params are valid, stack-local slots that outlive this
        // single synchronous FFI call; `DwmGetColorizationColor` only writes
        // through them before returning -- no aliasing, no retained pointers.
        let ok = unsafe {
            windows::Win32::Graphics::Dwm::DwmGetColorizationColor(&mut color, &mut opaque_blend)
        }
        .is_ok();
        if !ok {
            return None;
        }
        // Documented format: 0xAARRGGBB.
        Some(AccentColor {
            r: ((color >> 16) & 0xFF) as u8,
            g: ((color >> 8) & 0xFF) as u8,
            b: (color & 0xFF) as u8,
        })
    }

    pub(super) fn watch(_on_change: Box<dyn Fn(AccentColor) + Send + 'static>) -> bool {
        // No live-signal watcher on Windows in this pass: DWM colorization changes
        // arrive as a WM_DWMCOLORIZATIONCOLORCHANGED window message, which would
        // need a hook into Slint's winit event loop -- out of this task's scope.
        // `os_accent()` above is startup-only on Windows for now.
        false
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod imp {
    use super::AccentColor;

    /// macOS (and any other unhandled OS) has no accent read implemented yet —
    /// macOS support is P6 gap 32, blocked on hardware (`docs/devel/p6-gaps.md`).
    /// Always falls back to [`AccentColor::FALLBACK`].
    pub(super) fn read() -> Option<AccentColor> {
        None
    }

    pub(super) fn watch(_on_change: Box<dyn Fn(AccentColor) + Send + 'static>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_accent_never_panics_and_returns_a_color() {
        // Smoke test: whatever the host environment (portal present or not,
        // headless CI, etc.), this must return *a* color, never panic.
        let c = os_accent();
        // Trivial sanity: the type is inhabited / Copy-able.
        let _c2 = c;
    }

    #[test]
    fn fallback_matches_the_documented_cool_blue() {
        assert_eq!(
            AccentColor::FALLBACK,
            AccentColor {
                r: 0x3b,
                g: 0x82,
                b: 0xf6
            }
        );
    }
}
