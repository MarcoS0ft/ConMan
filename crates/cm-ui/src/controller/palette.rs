//! Command palette: open/filter/navigate/dispatch, and the static action list.
use std::cell::RefCell;
use std::rc::Rc;

use cm_session::PaneLayout;
use slint::{ComponentHandle, Model, SharedString, VecModel};

use crate::tree::cred_name_idx;
use crate::{AppWindow, PaletteAction, TabItem};

use crate::generated_ui::ConnProfile;

use super::*;

pub(super) fn wire_palette(ctx: &Ctx) {
    wire_open_palette(ctx);
    wire_palette_edited(ctx);
    wire_palette_activated(ctx);
}

fn wire_open_palette(ctx: &Ctx) {
    ctx.ui.on_open_palette({
        let weak = ctx.ui.as_weak();
        let pal_model = ctx.palette_model.clone();
        let tab_model_op = ctx.tab_model.clone();
        let state = ctx.state.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let labels: Vec<String> = state
                    .borrow()
                    .detached
                    .iter()
                    .map(|d| d.label.clone())
                    .collect();
                let tabs: Vec<(usize, String)> = (0..tab_model_op.row_count())
                    .filter_map(|i| tab_model_op.row_data(i).map(|t| (i, t.title.to_string())))
                    .collect();
                let q = ui.get_palette_query();
                rebuild_palette_model(&pal_model, &q, &labels, &tabs);
                ui.set_palette_selected(0);
                ui.set_palette_open(true);
            }
        }
    });
}

fn wire_palette_edited(ctx: &Ctx) {
    ctx.ui.on_palette_edited({
        let weak = ctx.ui.as_weak();
        let pal_model = ctx.palette_model.clone();
        let tab_model_pe = ctx.tab_model.clone();
        let state = ctx.state.clone();
        move |query| {
            let labels: Vec<String> = state
                .borrow()
                .detached
                .iter()
                .map(|d| d.label.clone())
                .collect();
            let tabs: Vec<(usize, String)> = (0..tab_model_pe.row_count())
                .filter_map(|i| tab_model_pe.row_data(i).map(|t| (i, t.title.to_string())))
                .collect();
            rebuild_palette_model(&pal_model, &query, &labels, &tabs);
            if let Some(ui) = weak.upgrade() {
                ui.set_palette_query(query);
                ui.set_palette_selected(0);
            }
        }
    });
}

fn wire_palette_activated(ctx: &Ctx) {
    ctx.ui.on_palette_activated({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let pal_model_dispatch = ctx.palette_model.clone();
        let weak = ctx.ui.as_weak();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                dispatch_palette_action(&state, &tab_model, &pal_model_dispatch, &ui, idx as usize);
            }
        }
    });
}

/// Collect the dynamic context needed to rebuild the palette:
/// returns `(detached_labels, tab_entries)`.
pub(super) fn collect_palette_context(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
) -> (Vec<String>, Vec<(usize, String)>) {
    let labels: Vec<String> = state
        .borrow()
        .detached
        .iter()
        .map(|d| d.label.clone())
        .collect();
    let tabs: Vec<(usize, String)> = (0..tab_model.row_count())
        .filter_map(|i| tab_model.row_data(i).map(|t| (i, t.title.to_string())))
        .collect();
    (labels, tabs)
}

pub(super) fn rebuild_palette_model(
    pal_model: &Rc<VecModel<PaletteAction>>,
    query: &SharedString,
    detached_labels: &[String],
    tab_entries: &[(usize, String)],
) {
    let filtered = filter_palette_actions(query.as_str(), detached_labels, tab_entries);
    while pal_model.row_count() > 0 {
        pal_model.remove(0);
    }
    for a in filtered {
        pal_model.push(a);
    }
}

pub(super) fn handle_palette_key(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    pal_model: &Rc<VecModel<PaletteAction>>,
    text: SharedString,
    special: i32,
    mods: i32,
) {
    match special {
        4 => {
            ui.set_palette_open(false);
            ui.set_palette_selected(0);
        }
        5 => {
            let cur = ui.get_palette_selected();
            if cur > 0 {
                ui.set_palette_selected(cur - 1);
            }
        }
        6 => {
            let cur = ui.get_palette_selected();
            let max = (pal_model.row_count() as i32).saturating_sub(1);
            if cur < max {
                ui.set_palette_selected(cur + 1);
            }
        }
        1 => {
            let idx = ui.get_palette_selected() as usize;
            ui.set_palette_open(false);
            ui.set_palette_selected(0);
            dispatch_palette_action(state, tab_model, pal_model, ui, idx);
        }
        3 if mods & 0b1001 == 0 => {
            let q = ui.get_palette_query();
            let new_q: String = {
                let mut s = q.as_str().to_owned();
                s.pop();
                s
            };
            let new_q = SharedString::from(new_q.as_str());
            let (labels, tabs) = collect_palette_context(state, tab_model);
            rebuild_palette_model(pal_model, &new_q, &labels, &tabs);
            ui.set_palette_query(new_q);
            ui.set_palette_selected(0);
        }
        0 if mods & 0b1001 == 0 && !text.is_empty() => {
            let q = ui.get_palette_query();
            let new_q = SharedString::from(format!("{}{}", q.as_str(), text.as_str()).as_str());
            let (labels, tabs) = collect_palette_context(state, tab_model);
            rebuild_palette_model(pal_model, &new_q, &labels, &tabs);
            ui.set_palette_query(new_q);
            ui.set_palette_selected(0);
        }
        _ => {}
    }
}

pub(super) fn dispatch_palette_action(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    palette_model: &Rc<VecModel<PaletteAction>>,
    ui: &AppWindow,
    idx: usize,
) {
    if idx >= palette_model.row_count() {
        return;
    }
    let action = palette_model.row_data(idx).unwrap_or_default();
    match action.label.as_str() {
        // ── ACTIONS ───────────────────────────────────────────────────────────
        "Quick connect\u{2026}" => ui.set_quick_connect_open(true),
        "New local tab" => tabs::open_local_tab(state, tab_model, ui),
        "New SSH connection" => {
            // Open the profile editor pre-set for SSH (kind index 0).
            let st = state.borrow();
            let selected_group_idx = tree_ctl::group_name_idx(None, st.conn_tree.groups());
            let cred_idx =
                cred_name_idx(None, st.keys_panel.credentials(), st.keys_panel.folders());
            drop(st);
            let form = ConnProfile {
                id: 0,
                name: SharedString::from(""),
                group_id: 0,
                kind: 0, // SSH
                host: SharedString::from(""),
                port: SharedString::from("22"),
                username: SharedString::from(""),
                auth_method: 1,
                selected_cred_idx: cred_idx,
                effective_cred_name: SharedString::from(""),
                effective_cred_username: SharedString::from(""),
                effective_inherited: false,
                selected_group_idx,
                rdp_domain: SharedString::from(""),
                rdp_resolution: SharedString::from(tree_ctl::default_rdp_resolution().as_str()),
                cred_mode: 0,
                inline_password: SharedString::from(""),
                inline_has_secret: false,
            };
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
        "New RDP connection" => {
            // Open the profile editor pre-set for RDP (kind index 1).
            let st = state.borrow();
            let selected_group_idx = tree_ctl::group_name_idx(None, st.conn_tree.groups());
            let cred_idx =
                cred_name_idx(None, st.keys_panel.credentials(), st.keys_panel.folders());
            drop(st);
            let form = ConnProfile {
                id: 0,
                name: SharedString::from(""),
                group_id: 0,
                kind: 1, // RDP
                host: SharedString::from(""),
                port: SharedString::from("3389"),
                username: SharedString::from(""),
                auth_method: 1,
                selected_cred_idx: cred_idx,
                effective_cred_name: SharedString::from(""),
                effective_cred_username: SharedString::from(""),
                effective_inherited: false,
                selected_group_idx,
                rdp_domain: SharedString::from(""),
                rdp_resolution: SharedString::from(tree_ctl::default_rdp_resolution().as_str()),
                cred_mode: 0,
                inline_password: SharedString::from(""),
                inline_has_secret: false,
            };
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
        "Close current tab" => {
            let active = state.borrow().active;
            tabs::close_tab(state, tab_model, ui, active);
        }
        "Toggle sidebar" => ui.set_sidebar_collapsed(!ui.get_sidebar_collapsed()),
        // ── PANELS ────────────────────────────────────────────────────────────
        "Focus Connections" => ui.set_active_panel(0),
        "Focus Keys" => ui.set_active_panel(1),
        "Open Settings" => ui.set_active_panel(2),
        // ── DATA ──────────────────────────────────────────────────────────────
        // P6.6: native save/open dialogs (`rfd`) wired to `cm_storage::json_io`.
        // Secrets are excluded by default on export (ARCHITECTURE §6); see
        // `import_export.rs` and `docs/devel/memos/P6.6-rfd-dep.md`.
        "Export connections\u{2026}" => {
            let io = state.borrow().io.clone();
            import_export::export_via_dialog(&io);
        }
        "Import connections\u{2026}" => {
            let io = state.borrow().io.clone();
            import_export::import_via_dialog(&io, state, ui);
        }
        // ── PANES ─────────────────────────────────────────────────────────────
        "Split horizontal" => panes::do_split(state, tab_model, ui, PaneLayout::HSplit),
        "Split vertical" => panes::do_split(state, tab_model, ui, PaneLayout::VSplit),
        "Close pane" => panes::do_close_pane(state, tab_model, ui, false),
        "Detach session" => panes::do_close_pane(state, tab_model, ui, true),
        "Toggle broadcast" => ui.set_broadcast_active(!ui.get_broadcast_active()),
        "Broadcast target\u{2026}" => ui.invoke_open_broadcast_target(),
        // ── TABS (dynamic) ────────────────────────────────────────────────────
        // "Switch to: <title>" — find the first tab with the matching title.
        label if label.starts_with("Switch to: ") => {
            let target = label.trim_start_matches("Switch to: ");
            let pos = (0..tab_model.row_count()).find(|&i| {
                tab_model
                    .row_data(i)
                    .map(|t| t.title.as_str() == target)
                    .unwrap_or(false)
            });
            if let Some(idx) = pos {
                tabs::select_tab(state, ui, idx as i32);
            }
        }
        // ── SESSIONS (dynamic) ────────────────────────────────────────────────
        // "Reattach: <label>" — find the matching detached entry.
        label if label.starts_with("Reattach: ") => {
            let target_label = label.trim_start_matches("Reattach: ").to_owned();
            let entry = {
                let mut st = state.borrow_mut();
                let pos = st.detached.iter().position(|d| d.label == target_label);
                pos.map(|p| st.detached.remove(p))
            };
            if let Some(d) = entry {
                panes::reattach_session(state, tab_model, ui, d);
            }
        }
        _ => {}
    }
}

pub(super) fn initial_palette_actions() -> Vec<PaletteAction> {
    vec![
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: true,
            label: SharedString::from("Quick connect\u{2026}"),
            detail: SharedString::from("SSH quick-connect form"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB2D}"), // cod-plug
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("New local tab"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EA60}"), // cod-add
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("New SSH connection"),
            detail: SharedString::from("Save a new SSH profile"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{F0317}"), // md-lan
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("New RDP connection"),
            detail: SharedString::from("Save a new RDP profile"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EA7A}"), // cod-vm
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Close current tab"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EA76}"), // cod-close
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Toggle sidebar"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB6A}"), // cod-three_bars
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANELS"),
            first_in_group: true,
            label: SharedString::from("Focus Connections"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{F0317}"), // md-lan
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANELS"),
            first_in_group: false,
            label: SharedString::from("Focus Keys"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB11}"), // cod-key
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANELS"),
            first_in_group: false,
            label: SharedString::from("Open Settings"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{F0493}"), // md-cog
            status: SharedString::from(""),
            selected: false,
        },
        // P6.6: export/import the full connection tree as versioned JSON
        // (secrets excluded by default; native save/open dialogs via `rfd`).
        PaletteAction {
            category: SharedString::from("DATA"),
            first_in_group: true,
            label: SharedString::from("Export connections\u{2026}"),
            detail: SharedString::from("Save groups, connections & credential refs as JSON"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EBAC}"), // cod-export
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("DATA"),
            first_in_group: false,
            label: SharedString::from("Import connections\u{2026}"),
            detail: SharedString::from("Load groups, connections & credential refs from JSON"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{F02FA}"), // md-import
            status: SharedString::from(""),
            selected: false,
        },
        // Split-pane + broadcast actions (P5.1).
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: true,
            label: SharedString::from("Split horizontal"),
            detail: SharedString::from("Side-by-side panes"),
            shortcut: SharedString::from("Ctrl+Shift+\\"),
            glyph: SharedString::from("\u{EB56}"), // cod-split_horizontal
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Split vertical"),
            detail: SharedString::from("Stacked panes"),
            shortcut: SharedString::from("Ctrl+Shift+-"),
            glyph: SharedString::from("\u{EB57}"), // cod-split_vertical
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Close pane"),
            detail: SharedString::from("Close pane and shut down session"),
            shortcut: SharedString::from("Ctrl+Shift+W"),
            glyph: SharedString::from("\u{EA76}"), // cod-close
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Detach session"),
            detail: SharedString::from("Close pane, keep session running"),
            shortcut: SharedString::from("Ctrl+Shift+D"),
            glyph: SharedString::from("\u{EAD0}"), // cod-debug_disconnect
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Toggle broadcast"),
            detail: SharedString::from("Fan input to the current broadcast target"),
            shortcut: SharedString::from("Ctrl+Shift+B"),
            glyph: SharedString::from("\u{EAAD}"), // cod-broadcast
            status: SharedString::from(""),
            selected: false,
        },
        // P6.11 (gap 14): keyboard-reachable entry point for the targeting
        // menu (which is otherwise a click-only popup off the broadcast
        // affordance) -- also gives the QA harness / xvfb-only test runs a
        // way to open it without real X11 pointer injection.
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Broadcast target\u{2026}"),
            detail: SharedString::from("Choose which panes receive broadcast input"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EAAD}"), // cod-broadcast (same family as "Toggle broadcast")
            status: SharedString::from(""),
            selected: false,
        },
    ]
}

pub(super) fn filter_palette_actions(
    query: &str,
    detached_labels: &[String],
    tab_entries: &[(usize, String)],
) -> Vec<PaletteAction> {
    // Build the full list: static actions + TABS + SESSIONS.
    let mut all = initial_palette_actions();
    // One "Switch to: <title>" entry per open tab.
    for (i, (tab_idx, title)) in tab_entries.iter().enumerate() {
        all.push(PaletteAction {
            category: SharedString::from("TABS"),
            first_in_group: i == 0,
            label: SharedString::from(format!("Switch to: {title}").as_str()),
            detail: SharedString::from(format!("tab {}", tab_idx + 1).as_str()),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EBCB}"), // cod-arrow_swap
            status: SharedString::from(""),
            selected: false,
        });
    }
    // One "Reattach: <label>" per detached session.
    for (i, label) in detached_labels.iter().enumerate() {
        all.push(PaletteAction {
            category: SharedString::from("SESSIONS"),
            first_in_group: i == 0,
            label: SharedString::from(format!("Reattach: {label}").as_str()),
            detail: SharedString::from("Restore detached session to a new tab"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB3A}"), // cod-remote
            status: SharedString::from(""),
            selected: false,
        });
    }
    if query.is_empty() {
        return all;
    }
    let q = query.to_lowercase();
    let mut first_in_group = true;
    all.into_iter()
        .filter(|a| a.label.to_lowercase().contains(&q))
        .map(|mut a| {
            a.first_in_group = first_in_group;
            first_in_group = false;
            a
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_filter_empty_query_returns_all() {
        let all = filter_palette_actions("", &[], &[]);
        let initial = initial_palette_actions();
        assert_eq!(all.len(), initial.len());
        for (a, b) in all.iter().zip(initial.iter()) {
            assert_eq!(a.label, b.label);
        }
    }

    #[test]
    fn palette_filter_no_match_returns_empty() {
        let result = filter_palette_actions("xyzzy_no_such_action", &[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn palette_contains_new_ssh_connection() {
        let all = initial_palette_actions();
        assert!(all.iter().any(|a| a.label.as_str() == "New SSH connection"));
    }

    #[test]
    fn palette_contains_new_rdp_connection() {
        let all = initial_palette_actions();
        assert!(all.iter().any(|a| a.label.as_str() == "New RDP connection"));
    }

    #[test]
    fn palette_contains_close_current_tab() {
        let all = initial_palette_actions();
        assert!(all.iter().any(|a| a.label.as_str() == "Close current tab"));
    }

    #[test]
    fn palette_contains_quick_connect() {
        let all = initial_palette_actions();
        assert!(
            all.iter()
                .any(|a| a.label.as_str().starts_with("Quick connect"))
        );
    }

    #[test]
    fn palette_filter_narrows_by_label() {
        let result = filter_palette_actions("sidebar", &[], &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Toggle sidebar");
    }

    #[test]
    fn palette_filter_first_row_always_has_group_header() {
        let result = filter_palette_actions("split", &[], &[]);
        assert!(
            !result.is_empty(),
            "expected at least one result for 'split'"
        );
        assert!(result[0].first_in_group);
    }

    #[test]
    fn palette_filter_includes_reattach_entries() {
        let labels = vec!["server1".to_owned(), "server2".to_owned()];
        let all = filter_palette_actions("", &labels, &[]);
        let reattach: Vec<_> = all
            .iter()
            .filter(|a| a.label.as_str().starts_with("Reattach: "))
            .collect();
        assert_eq!(reattach.len(), 2);
        assert_eq!(reattach[0].label.as_str(), "Reattach: server1");
        assert_eq!(reattach[0].category.as_str(), "SESSIONS");
        assert!(reattach[0].first_in_group);
        assert!(!reattach[1].first_in_group);
    }

    #[test]
    fn palette_filter_reattach_matches_query() {
        let labels = vec!["prod-server".to_owned(), "staging".to_owned()];
        let result = filter_palette_actions("prod", &labels, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Reattach: prod-server");
    }

    #[test]
    fn palette_filter_includes_switch_to_tab_entries() {
        let tabs = vec![
            (0usize, "web-dev-01".to_owned()),
            (1usize, "local".to_owned()),
        ];
        let all = filter_palette_actions("", &[], &tabs);
        let switch: Vec<_> = all
            .iter()
            .filter(|a| a.label.as_str().starts_with("Switch to: "))
            .collect();
        assert_eq!(switch.len(), 2);
        assert_eq!(switch[0].label.as_str(), "Switch to: web-dev-01");
        assert_eq!(switch[0].category.as_str(), "TABS");
        assert!(switch[0].first_in_group);
    }

    #[test]
    fn palette_filter_switch_to_tab_matches_query() {
        let tabs = vec![
            (0usize, "web-dev-01".to_owned()),
            (1usize, "local".to_owned()),
        ];
        let result = filter_palette_actions("web", &[], &tabs);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Switch to: web-dev-01");
    }

    #[test]
    fn rebuild_palette_model_replaces_not_appends() {
        let model: Rc<VecModel<PaletteAction>> = Rc::new(VecModel::default());
        rebuild_palette_model(&model, &SharedString::from(""), &[], &[]);
        let first_count = model.row_count();
        rebuild_palette_model(&model, &SharedString::from(""), &[], &[]);
        assert_eq!(model.row_count(), first_count);
    }

    #[test]
    fn handle_palette_key_mod_bitmask_plain_is_zero() {
        let plain: i32 = 0;
        let ctrl: i32 = 1;
        let meta: i32 = 8;
        assert_eq!(plain & 0b1001, 0);
        assert_ne!(ctrl & 0b1001, 0);
        assert_ne!(meta & 0b1001, 0);
    }

    #[test]
    fn palette_contains_export_and_import_actions() {
        let all = initial_palette_actions();
        assert!(
            all.iter()
                .any(|a| a.label.as_str() == "Export connections\u{2026}"),
            "Export action must exist"
        );
        assert!(
            all.iter()
                .any(|a| a.label.as_str() == "Import connections\u{2026}"),
            "Import action must exist"
        );
    }
}
