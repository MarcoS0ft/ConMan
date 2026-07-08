//! P8.1 — accessibility/element-identity contract audit.
//!
//! This test IS the maintenance rule from
//! `docs/devel/tasks/P8.1-a11y-element-contract.md` ("the contract's item 6"):
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
    [
        // Pre-existing placeholder icon in the activity bar (glyph "md-account_group",
        // see docs/devel/p5.4-os-gaps.md) with no `clicked` handler and no wired
        // behavior — inert since before this task. Inventing a label for a
        // non-functional control would be dishonest a11y; wiring it up is a
        // separate, out-of-scope feature. Revisit (wire behavior + give it a real
        // label) when this icon is actually turned into a feature.
        "AppWindow::team-placeholder-btn",
    ]
    .into_iter()
    .collect()
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
        "P8.1 a11y audit found {} violation(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}
