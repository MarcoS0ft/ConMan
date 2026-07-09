//! P8.4 Suite -- Settings: theme dark/light toggle, density compact/cosy
//! toggle, and accent-preset selection. Covers the P6.17 Linux J3 / Windows
//! W3 journey ("Settings: theme dark<->light + density compact<->cosy") that
//! P8.2's three suites did not port (`suite_dialogs.rs` / `suite_shell.rs` /
//! `suite_overlays.rs` never open the Settings panel).
//!
//! Scope note (honest limit, matches the p8-plan.md layer table): this suite
//! asserts the MODEL -- `Theme.dark-mode`/`Theme.density`/`Theme.accent-index`
//! aliased onto `AppWindow` (`ui.get_dark_mode()`/`get_density()`/
//! `get_accent_index()`), and that the real `SegmentedControl`/swatch elements
//! drive them via their real `accessible-action-default`. It does NOT assert
//! that a dark-mode toggle visually recolors already-open chrome/grids pixel-
//! for-pixel (that is the `visual:theme-toggle-recolor` check --
//! `memos/P8.4-qa-gate-rubric.md` -- the F-grid/P6.17-V1 class the testing
//! backend's "no pixels" honest limit puts out of this layer's reach).

#![cfg(feature = "ui-introspection")]

mod support;

use support::{find_by_id, find_descendant_by_label, find_singleton, harness, pump_ticks};

#[test]
fn settings_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    open_settings_panel();
    theme_dark_light_toggle_updates_dark_mode();
    density_compact_cosy_toggle();
    accent_preset_selection();
    render_backend_toggle_persists();
    #[cfg(feature = "agent-mode")]
    agent_mode_section_toggles_persist();
}

/// Opens Settings via the real command-palette flow (mirrors
/// `suite_shell.rs::palette_open_filter_dispatch`) and returns nothing --
/// each scenario below re-opens it on its own fresh harness so scenarios
/// never see each other's Settings state.
fn open_settings(h: &cm_ui::TestHarness) {
    find_by_id(&h.ui, "AppWindow::palette-badge-btn").invoke_accessible_default_action();
    let input = find_by_id(&h.ui, "CommandPalette::input");
    input.set_accessible_value("open settings");
    let palette = find_singleton(&h.ui, "CommandPalette");
    let row = find_descendant_by_label(&palette, "Open Settings");
    row.invoke_accessible_default_action();
}

/// Just proves the palette route reaches the Settings panel (`active-panel`
/// == 2, per `app.slint`'s activity-bar indexing) before the more specific
/// scenarios below drive its controls.
fn open_settings_panel() {
    let (h, _repo, _provider) = harness();
    open_settings(&h);
    assert_eq!(
        h.ui.get_active_panel(),
        2,
        "palette must switch to Settings"
    );
    find_singleton(&h.ui, "SettingsPanel");
}

/// J3/W3: clicking the Theme segmented control's "Light"/"Dark" options
/// (real `SegmentedControl` elements, not property pokes) must flip
/// `Theme.dark-mode` (aliased as `AppWindow::dark-mode`) -- the same
/// `ui.get_dark_mode()` read the P6.8 terminal-repaint handler depends on.
fn theme_dark_light_toggle_updates_dark_mode() {
    let (h, _repo, _provider) = harness();
    open_settings(&h);
    let panel = find_singleton(&h.ui, "SettingsPanel");

    find_descendant_by_label(&panel, "Light").invoke_accessible_default_action();
    pump_ticks(1);
    assert!(!h.ui.get_dark_mode(), "Light must clear dark-mode");

    find_descendant_by_label(&panel, "Dark").invoke_accessible_default_action();
    pump_ticks(1);
    assert!(h.ui.get_dark_mode(), "Dark must set dark-mode");
}

/// J3/W3's density half: Compact/Cosy is index 0/1 on `Theme.density`
/// (aliased `AppWindow::density`).
fn density_compact_cosy_toggle() {
    let (h, _repo, _provider) = harness();
    open_settings(&h);
    let panel = find_singleton(&h.ui, "SettingsPanel");

    find_descendant_by_label(&panel, "Cosy").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_density(), 1, "Cosy must select density index 1");

    find_descendant_by_label(&panel, "Compact").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_density(), 0, "Compact must select density index 0");
}

/// Accent swatches (`Accent preset N`, 1-indexed per the P8.1 a11y contract's
/// "honest ordinal, no fabricated color name" note) are a radio group:
/// selecting one updates `accent-index` and its own `accessible-checked`
/// flips to `true` while the previously-selected swatch's flips to `false`.
fn accent_preset_selection() {
    let (h, _repo, _provider) = harness();
    open_settings(&h);
    let panel = find_singleton(&h.ui, "SettingsPanel");

    assert_eq!(
        h.ui.get_accent_index(),
        0,
        "accent defaults to preset 1 (index 0)"
    );
    let preset1 = find_descendant_by_label(&panel, "Accent preset 1");
    assert_eq!(preset1.accessible_checked(), Some(true));

    find_descendant_by_label(&panel, "Accent preset 2").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(
        h.ui.get_accent_index(),
        1,
        "selecting preset 2 must update accent-index"
    );

    let panel = find_singleton(&h.ui, "SettingsPanel");
    assert_eq!(
        find_descendant_by_label(&panel, "Accent preset 2").accessible_checked(),
        Some(true),
        "preset 2 must now read checked"
    );
    assert_eq!(
        find_descendant_by_label(&panel, "Accent preset 1").accessible_checked(),
        Some(false),
        "preset 1 must no longer read checked"
    );
}

/// P7.1 cont.: the Rendering segmented control (Auto/Software/Hardware) drives
/// `render-backend` (aliased `AppWindow::render-backend`) AND persists the
/// mapped `render.backend` string ("auto"/"software"/"accelerated") via the
/// real controller handler. The renderer only switches on next launch, so this
/// asserts the model + persistence, not a live renderer swap.
fn render_backend_toggle_persists() {
    use cm_core::SettingsService;

    let (h, repo, _provider) = harness();
    open_settings(&h);
    let panel = find_singleton(&h.ui, "SettingsPanel");

    assert_eq!(
        h.ui.get_render_backend(),
        0,
        "renderer defaults to Auto (index 0)"
    );

    find_descendant_by_label(&panel, "Software").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_render_backend(), 1, "Software selects index 1");
    assert_eq!(
        SettingsService::new(repo.as_ref())
            .load_renderer_backend()
            .unwrap()
            .as_deref(),
        Some("software"),
        "Software must persist render.backend=software"
    );

    find_descendant_by_label(&panel, "Hardware").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_render_backend(), 2, "Hardware selects index 2");
    assert_eq!(
        SettingsService::new(repo.as_ref())
            .load_renderer_backend()
            .unwrap()
            .as_deref(),
        Some("accelerated"),
        "Hardware must persist render.backend=accelerated"
    );

    find_descendant_by_label(&panel, "Auto").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_render_backend(), 0, "Auto selects index 0");
    // "auto" clears the cache -> load_renderer_backend collapses it to None.
    assert_eq!(
        SettingsService::new(repo.as_ref())
            .load_renderer_backend()
            .unwrap(),
        None,
        "Auto must clear the persisted backend (re-probe next launch)"
    );
}

/// P8.6-B: only compiled/run when this binary was built with BOTH
/// `ui-introspection` and `agent-mode` -- `agent-mode-available` (and hence
/// the whole Automation section) is otherwise `false` and nothing below
/// would exist in the tree at all (see `AgentModeConfig`'s doc comment for
/// why the section's *markup* still ships either way, just inert). No
/// harness scenario starts a real agent-mode proxy (that is `conman`'s own
/// process, out of scope for this in-process harness) -- this only exercises
/// the Settings UI's persistence, matching `render_backend_toggle_persists`'s
/// shape.
#[cfg(feature = "agent-mode")]
fn agent_mode_section_toggles_persist() {
    use cm_core::SettingsService;

    let (h, repo, _provider) = harness();
    open_settings(&h);
    let panel = find_singleton(&h.ui, "SettingsPanel");

    assert!(!h.ui.get_agent_mode_enabled(), "agent mode defaults to off");
    assert!(
        !SettingsService::new(repo.as_ref())
            .load_automation()
            .unwrap()
            .enabled,
        "automation.enabled defaults to off"
    );

    find_descendant_by_label(&panel, "Enable agent mode").invoke_accessible_default_action();
    pump_ticks(1);
    assert!(
        h.ui.get_agent_mode_enabled(),
        "toggling the checkbox must flip the model"
    );
    assert!(
        SettingsService::new(repo.as_ref())
            .load_automation()
            .unwrap()
            .enabled,
        "toggling must persist automation.enabled=true"
    );

    find_descendant_by_label(&panel, "Read").invoke_accessible_default_action();
    pump_ticks(1);
    let persisted = SettingsService::new(repo.as_ref())
        .load_automation()
        .unwrap()
        .scopes;
    assert!(
        persisted.read,
        "Read checkbox must persist to automation.scopes"
    );
    assert!(!persisted.write, "Write must stay ungranted");
    assert!(!persisted.execute, "Execute must stay ungranted");
}
