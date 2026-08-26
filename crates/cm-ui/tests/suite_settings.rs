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

use i_slint_backend_testing::ElementHandle;
use slint::{ComponentHandle, Model};
use support::{find_by_id, find_descendant_by_label, find_singleton, harness, pump_ticks};

#[test]
fn settings_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    open_settings_panel();
    theme_dark_light_toggle_updates_dark_mode();
    density_compact_cosy_toggle();
    accent_preset_selection();
    stale_font_family_uses_effective_default();
    font_family_selection_persists();
    settings_body_scrolls_beneath_fixed_header();
    render_backend_toggle_persists();
    #[cfg(feature = "agent-mode")]
    agent_mode_section_toggles_persist();
}

fn font_family_selection_persists() {
    use cm_core::{DEFAULT_TERMINAL_FONT_FAMILY, SettingsService};

    let (h, repo, _provider) = harness();
    open_settings(&h);
    let panel = find_singleton(&h.ui, "SettingsPanel");
    let combo = find_descendant_by_label(&panel, "Terminal font family");
    let families = h.ui.get_settings_font_families();

    assert_eq!(
        h.ui.get_settings_font_family().as_str(),
        DEFAULT_TERMINAL_FONT_FAMILY,
        "the selector must present the effective default family"
    );
    assert_eq!(
        combo.accessible_value().as_deref(),
        Some(DEFAULT_TERMINAL_FONT_FAMILY),
        "the default family must be selected in the ComboBox"
    );
    assert!(
        families.row_count() >= 1,
        "the usable family list must not be empty"
    );
    assert_eq!(
        families.row_data(0).as_deref(),
        Some(DEFAULT_TERMINAL_FONT_FAMILY),
        "the bundled default must be the first deterministic option"
    );

    let selected_index = usize::from(families.row_count() > 1);
    let selected_family = families
        .row_data(selected_index)
        .expect("selected usable family must exist");

    combo.invoke_accessible_expand_action();
    pump_ticks(1);
    ElementHandle::find_by_accessible_label(&h.ui, selected_family.as_str())
        .next()
        .expect("owner-enumerated family must be present in the expanded ComboBox");
    // The testing backend exposes ComboBox expansion/options but no public
    // semantic "select item" action. Drive the same Slint bridge values that
    // ComboBox::selected writes and verify the real controller callback.
    h.ui.set_settings_font_family_index(selected_index as i32);
    h.ui.set_settings_font_family(selected_family.clone());
    h.ui.invoke_settings_font_family_changed(selected_family.clone());
    pump_ticks(1);

    assert_eq!(h.ui.get_settings_font_family(), selected_family);
    assert_eq!(
        SettingsService::new(repo.as_ref())
            .load()
            .expect("load settings")
            .font_family,
        selected_family.as_str(),
        "selecting a family must persist the backend-reported effective family"
    );
}

fn stale_font_family_uses_effective_default() {
    use std::sync::Arc;

    use cm_core::{ConnectionRepository, DEFAULT_TERMINAL_FONT_FAMILY};
    use cm_storage::SqliteRepository;
    use support::{MockSessionProvider, NullCredentialStore};

    let repo: Arc<dyn ConnectionRepository> =
        Arc::new(SqliteRepository::open_in_memory().expect("open in-memory repository"));
    repo.set_setting("terminal.font_family", "Definitely Missing Font")
        .expect("seed stale family");
    let provider = MockSessionProvider::new();
    let h = cm_ui::build_for_test(cm_ui::AppConfig {
        repo,
        secrets: Arc::new(NullCredentialStore),
        session_provider: provider,
        activation_rx: None,
        first_launch: true,
        agent_mode: None,
    });
    h.ui.window()
        .set_size(slint::LogicalSize::new(1600.0, 1200.0));

    assert_eq!(
        h.ui.get_settings_font_family().as_str(),
        DEFAULT_TERMINAL_FONT_FAMILY,
        "a stale stored family must present the backend's effective default"
    );
    assert_eq!(h.ui.get_settings_font_family_index(), 0);
    assert_eq!(
        h.ui.get_settings_font_families().row_data(0).as_deref(),
        Some(DEFAULT_TERMINAL_FONT_FAMILY)
    );
}

fn settings_body_scrolls_beneath_fixed_header() {
    let (h, _repo, _provider) = harness();
    h.ui.window()
        .set_size(slint::LogicalSize::new(900.0, 420.0));
    open_settings(&h);
    pump_ticks(1);

    let header = find_by_id(&h.ui, "SettingsPanel::settings-header");
    let scroll = find_by_id(&h.ui, "SettingsPanel::settings-scroll");
    let header_position = header.absolute_position();
    assert!(
        scroll.absolute_position().y >= header_position.y + header.size().height,
        "the scrolling viewport must begin beneath the fixed header"
    );
    assert!(
        scroll.size().height > 0.0 && scroll.size().height < 420.0,
        "the settings body must receive a bounded viewport at constrained height"
    );

    // Reach the bottom with the real wheel route, then capture the specific
    // final shortcut. A generic "some ShortcutRow exists" assertion can pass
    // even when the bottom content never becomes reachable.
    scroll.scroll(0.0, -10_000.0);
    pump_ticks(1);
    let bottom_row = find_by_id(&h.ui, "SettingsPanel::global-ctrl-k-shortcut");
    let bottom_row_before = bottom_row.absolute_position();

    // Move slightly back toward the top. The content must translate downward
    // while Ctrl K remains inside the viewport (the bottom padding provides a
    // stable margin for this constrained-height check).
    scroll.scroll(0.0, 8.0);
    pump_ticks(1);

    let header_after = find_by_id(&h.ui, "SettingsPanel::settings-header");
    assert_eq!(
        header_after.absolute_position(),
        header_position,
        "scrolling settings content must not move the header"
    );
    let bottom_row_after = find_by_id(&h.ui, "SettingsPanel::global-ctrl-k-shortcut");
    let bottom_row_after_position = bottom_row_after.absolute_position();
    assert!(
        bottom_row_after_position.y > bottom_row_before.y,
        "scrolling toward the top must move the bottom shortcut downward"
    );
    let viewport_top = scroll.absolute_position().y;
    let viewport_bottom = viewport_top + scroll.size().height;
    let row_top = bottom_row_after_position.y;
    let row_bottom = row_top + bottom_row_after.size().height;
    assert!(
        row_top >= viewport_top && row_bottom <= viewport_bottom,
        "Ctrl K bounds ({row_top}..{row_bottom}) must fit the Settings viewport \
         ({viewport_top}..{viewport_bottom}) after scrolling"
    );
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
