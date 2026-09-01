//! Accessibility and element-identity contract audit.
//!
//! This test IS the maintenance rule from
//! The audit checks the accessibility contract:
//! any new interactive element or dialog must ship with an id + role + label
//! in the same change, or this test fails, naming exactly which element is
//! missing what.
//!
//! Requires the `ui-introspection` feature (compiles `ui/app.slint` with
//! Slint compiler debug info — see `build.rs`); without it, every
//! `ElementHandle` query below returns nothing
//! (`i_slint_backend_testing::search_api::warn_missing_debug_info`).
//!
//! Run with: `cargo test -p cm-ui --features ui-introspection`

#![cfg(feature = "ui-introspection")]

use std::collections::HashSet;
use std::ops::ControlFlow;

use i_slint_backend_testing::{AccessibleRole, ElementHandle, ElementRoot};

/// Roles that must carry a non-empty `accessible-label`.
///
/// This is a superset of "interactive" in the strict widget sense: it also
/// includes `Groupbox`, because the contract's dialog convention (no Slint
/// 1.17 `dialog` role) is `accessible-role: groupbox` + `accessible-label:
/// "<Title> dialog"` — a dialog root is exactly the "... or dialog" half of
/// the maintenance rule ("any new interactive element or dialog").
///
/// Deliberately excluded (containers/landmarks/auto-labeled builtins that do
/// NOT need a label of their own — the audit would be noise otherwise):
/// `None`, `List`, `TabList`, `TabPanel`, `Table`, `Tree`, `Image`,
/// `ProgressIndicator`, `RadioGroup`, and the landmark roles (`Region`,
/// `Main`, `Navigation`, `Banner`, `Complementary`, `ContentInfo`, `Form`,
/// `Search`). `Text`/`TextInput` are excluded too: Slint's own compiler
/// auto-binds their role+label/value (`lower_accessibility.rs`), so an
/// unlabeled bare `Text` can't actually happen — and requiring it here would
/// flag every decorative caption in the app.
fn roles_requiring_label() -> HashSet<AccessibleRole> {
    [
        AccessibleRole::Button,
        AccessibleRole::Checkbox,
        AccessibleRole::Combobox,
        AccessibleRole::Slider,
        AccessibleRole::Spinbox,
        AccessibleRole::Switch,
        AccessibleRole::RadioButton,
        AccessibleRole::Tab,
        AccessibleRole::ListItem,
        AccessibleRole::Groupbox,
    ]
    .into_iter()
    .collect()
}

/// Shared components (`components.slint`) that are always click-driven and
/// MUST carry an `accessible-role` wherever they're used or inherited from.
/// This is rule (b) of the audit: a defensive net against a future component
/// declaring `inherits IconButton`-style reuse of one of these and losing the
/// role binding along the way. Nothing in the current tree actually
/// `inherits` these (they're all used by composition, not inheritance), so
/// this mostly guards against regressions in components.slint itself, caught
/// instead by the type-name check below.
fn known_shared_interactive_types() -> HashSet<&'static str> {
    [
        "IconButton",
        "PrimaryButton",
        "SecondaryButton",
        "ActivityBarButton",
    ]
    .into_iter()
    .collect()
}

/// Genuine, individually-justified exceptions. Every entry needs a comment —
/// this list is deliberately short; anything else the audit finds is a real
/// gap to fix, not a candidate for allowlisting.
fn allowlisted_ids() -> HashSet<&'static str> {
    HashSet::new()
}

#[test]
fn all_interactive_elements_and_dialogs_are_labeled() {
    i_slint_backend_testing::init_no_event_loop();

    let app = cm_ui::AppWindow::new().expect("AppWindow::new() failed");

    let must_label = roles_requiring_label();
    let shared_interactive = known_shared_interactive_types();
    let allowlist = allowlisted_ids();

    let mut violations: Vec<String> = Vec::new();

    app.root_element().visit_descendants(|elem: ElementHandle| {
        let id = elem.id().map(|s| s.to_string());
        let id_str = id.as_deref().unwrap_or("<no id>");

        if allowlist.contains(id_str) {
            return ControlFlow::<()>::Continue(());
        }

        // Rule (a): an interactive role (or dialog groupbox) with no label.
        if let Some(role) = elem.accessible_role()
            && must_label.contains(&role)
        {
            let label_empty = match elem.accessible_label() {
                Some(l) => l.is_empty(),
                None => true,
            };
            if label_empty {
                violations.push(format!(
                    "unlabeled element: id={id_str} role={role:?} type={:?}",
                    elem.type_name().map(|t| t.to_string())
                ));
            }
        }

        // Rule (b): instantiates (or inherits from) a shared interactive
        // component but carries no accessible-role at all.
        let type_name = elem.type_name().map(|t| t.to_string());
        let inherits_shared = type_name
            .as_deref()
            .is_some_and(|t| shared_interactive.contains(t))
            || elem
                .bases()
                .is_some_and(|mut bases| bases.any(|b| shared_interactive.contains(b.as_str())));
        if inherits_shared && elem.accessible_role().is_none() {
            violations.push(format!(
                "shared interactive component with no accessible-role: id={id_str} type={type_name:?}"
            ));
        }

        ControlFlow::Continue(())
    });

    assert!(
        violations.is_empty(),
        "Accessibility audit found {} violation(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Password `FormField`s must not leak cleartext through
/// `accessible-value` (or any sibling accessibility sink) to introspection.
///
/// The test sets a
/// sentinel secret into the quick-connect dialog's password field (`qc-secret`,
/// rendered by `qc-password-field := FormField { password: true; text <=>
/// root.secret; }` in `screens/dialogs.slint`) and a *different* sentinel into
/// a non-password field in the same dialog (`qc-host`, rendered by
/// `qc-host-field := FormField { text <=> root.host; }`), then walks the
/// whole element tree.
///
/// `qc-kind` defaults to 0 (SSH) and `qc-auth-method` defaults to 1
/// (Password) in `app.slint`, so `qc-password-field` and `qc-host-field` are
/// both present without opening the quick-connect `Modal` — `Modal` only
/// toggles `visible`, it does not conditionally instantiate its `@children`.
///
/// Two assertions, both load-bearing:
///  1. The secret sentinel never appears in any element's `accessible_value`
///     or `accessible_description`. This is the runtime proof that
///     `components.slint`'s password branch (a raw `TextInput`-based
///     `edit-secure` + accessible-carrier wrapper, NOT std `LineEdit`) never
///     surfaces the cleartext — see the long comment above `FormField`'s
///     password branch for why a direct `accessible-value` override on std
///     `LineEdit` does NOT work (its widget-internal `accessible-value <=>
///     text` two-way alias silently wins over any override attempted from
///     the instantiation site, confirmed empirically while building this
///     test). If the mechanism regressed back to routing the real secret
///     through a std `LineEdit`, this assertion fails with the secret
///     sentinel showing up verbatim.
///  2. The non-password sentinel DOES surface via some element's
///     `accessible_value`. This is the "teeth" check: it proves the
///     carve-out is targeted at password fields only, not a blanket disable
///     of `accessible-value` — a regression that blanked every `FormField`
///     (e.g. `accessible-value: ""` unconditionally) would satisfy assertion
///     1 but fail this one.
#[test]
fn password_fields_never_expose_cleartext_via_accessibility() {
    i_slint_backend_testing::init_no_event_loop();

    let app = cm_ui::AppWindow::new().expect("AppWindow::new() failed");

    const SECRET_SENTINEL: &str = "SENTINEL-SECRET-XYZ";
    const PLAIN_SENTINEL: &str = "SENTINEL-PLAIN-ABC";

    // Open the quick-connect Modal: `visible: open` on `Modal` (dialogs.slint)
    // means invisible/clipped items may be excluded from the accessibility
    // tree by the backend, so open it to get a faithful walk of what a real
    // screen reader would see once the user opens quick-connect.
    app.set_quick_connect_open(true);
    app.set_qc_secret(SECRET_SENTINEL.into());
    app.set_qc_host(PLAIN_SENTINEL.into());

    // The masking-only contract: the real `text`/edit data path must be
    // untouched by the accessibility carve-out. `qc-password-field`'s
    // `text <=> root.secret` (dialogs.slint) still round-trips the actual
    // secret through `FormField.text` into `qc_secret` — only the
    // *accessible* surface is masked, not the model.
    assert_eq!(
        app.get_qc_secret().as_str(),
        SECRET_SENTINEL,
        "Password FormField's text/model path must be unaffected by the \
         accessibility carve-out — masking is accessible-surface-only"
    );

    let mut secret_leaks: Vec<String> = Vec::new();
    let mut plain_surfaced = false;

    app.root_element().visit_descendants(|elem: ElementHandle| {
        let id = elem.id().map(|s| s.to_string());
        let id_str = id.as_deref().unwrap_or("<no id>");

        if let Some(v) = elem.accessible_value()
            && v.contains(SECRET_SENTINEL)
        {
            secret_leaks.push(format!("accessible_value on id={id_str}: {v:?}"));
        }
        if let Some(d) = elem.accessible_description()
            && d.contains(SECRET_SENTINEL)
        {
            secret_leaks.push(format!("accessible_description on id={id_str}: {d:?}"));
        }
        if let Some(v) = elem.accessible_value()
            && v.contains(PLAIN_SENTINEL)
        {
            plain_surfaced = true;
        }

        ControlFlow::<()>::Continue(())
    });

    assert!(
        secret_leaks.is_empty(),
        "Password secret leaked through accessibility introspection:\n{}",
        secret_leaks.join("\n")
    );
    assert!(
        plain_surfaced,
        "Password test has no teeth: the non-password sentinel never surfaced via \
         accessible_value anywhere in the tree, so this test can't distinguish a \
         targeted carve-out from a blanket accessible-value disable"
    );
}
