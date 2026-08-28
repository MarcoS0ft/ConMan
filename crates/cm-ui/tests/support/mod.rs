//! Shared scaffolding for the P8.2 in-process element-test suites
//! (`suite_dialogs.rs` / `suite_shell.rs` / `suite_overlays.rs`).
//!
//! Not a test binary of its own -- Cargo only auto-registers direct children
//! of `tests/` as integration-test binaries, so each suite declares `mod
//! support;` (which resolves to this file) separately. Some duplicated
//! compilation across the three suite binaries is the accepted cost of the
//! "one binary per suite" structure the task spec requires (each suite needs
//! its own process: `init_integration_test_with_mock_time()` may only run
//! once per process).
//!
//! Gated on `ui-introspection` like the suites themselves: `cm_ui::AppConfig`/
//! `TestHarness`/`build_for_test` all exist unconditionally, but there is
//! nothing useful to do with the resulting `AppWindow` without the compiler
//! debug info this feature turns on (every `ElementHandle` query would come
//! back empty).

#![cfg(feature = "ui-introspection")]
#![allow(dead_code)] // not every suite uses every helper.

pub(crate) mod mock_provider;
pub(crate) mod mock_store;

pub(crate) use mock_provider::MockSessionProvider;
pub(crate) use mock_store::NullCredentialStore;

use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use cm_core::ConnectionRepository;
use cm_storage::SqliteRepository;
use cm_ui::{AppConfig, TestHarness};
use i_slint_backend_testing::{ElementHandle, ElementQuery, ElementRoot};
use slint::ComponentHandle;

/// The controller's real redraw-timer cadence
/// (`controller/mod.rs::REDRAW_INTERVAL`, private to that crate) mirrored
/// here as the mock-tick step, so [`pump_until`]/[`pump_ticks`] advance mock
/// time in the same granularity the real tick timer runs at.
pub(crate) const REDRAW_TICK: Duration = Duration::from_millis(16);

/// Builds a fresh, fully hermetic harness for one test scenario: an
/// in-memory SQLite repo (never touches disk), a no-op credential store, and
/// a [`MockSessionProvider`] the caller gets a handle to for scripting
/// connect/spawn behavior. `first_launch: true` is the simplest deterministic
/// start (one plain local-shell tab, no Launchpad/restore-session branching
/// to account for in every suite).
///
/// Returns `(harness, repo, provider)` -- `repo` and `provider` are the exact
/// `Arc`s the running app holds (not copies), so a scenario can assert
/// against `repo.list_connections()` after driving a Save, or mutate a status
/// cell it handed to `provider` to move a scripted session forward.
pub(crate) fn harness() -> (
    TestHarness,
    Arc<dyn ConnectionRepository>,
    Arc<MockSessionProvider>,
) {
    harness_with(true)
}

/// P8.4: like [`harness`], but lets the caller pick `first_launch` --
/// `suite_launchpad.rs` needs `false` to reach the Launchpad-fronted empty
/// tab (`assemble`'s `if first_launch { open_local_tab } else if
/// restore_snapshot.is_none() { open_empty_tab }` branch in
/// `controller/mod.rs`); every other suite keeps using plain [`harness`]'s
/// `true` (the simplest deterministic start, see this module's original
/// doc).
pub(crate) fn harness_with(
    first_launch: bool,
) -> (
    TestHarness,
    Arc<dyn ConnectionRepository>,
    Arc<MockSessionProvider>,
) {
    // P8.6-B: no suite drives the agent-mode proxy (that's conman's own
    // process, out of scope for this in-process harness) -- every ordinary
    // scenario runs as if agent-mode were off. See `harness_with_agent_mode`
    // for the execute-gate suites, which need a live `AgentModeConfig`.
    harness_with_agent_mode(first_launch, None)
}

/// Like [`harness_with`], but lets the caller install a live
/// `cm_ui::AgentModeConfig` -- the P8.6-B execute-gate suites (Reconnect /
/// "Connect in split") need this to exercise `agent_mode_execute_blocked`'s
/// real call sites end to end, not just the pure decision function
/// `controller::sessions` already unit-tests in isolation.
pub(crate) fn harness_with_agent_mode(
    first_launch: bool,
    agent_mode: Option<cm_ui::AgentModeConfig>,
) -> (
    TestHarness,
    Arc<dyn ConnectionRepository>,
    Arc<MockSessionProvider>,
) {
    let repo: Arc<dyn ConnectionRepository> =
        Arc::new(SqliteRepository::open_in_memory().expect("open in-memory SqliteRepository"));
    let provider = MockSessionProvider::new();
    let config = AppConfig {
        repo: repo.clone(),
        secrets: Arc::new(NullCredentialStore),
        session_provider: provider.clone(),
        secure_clipboard_root: None,
        activation_rx: None,
        first_launch,
        agent_mode,
    };
    let harness = cm_ui::build_for_test(config);
    // The testing backend's default window is 800x600 physical px
    // (`testing_backend.rs`'s `TestingWindow::size` fallback) -- too small
    // for some scrolling dialogs (`ProfileEditor`'s field column) to lay out
    // every field within the viewport, which would silently drop
    // off-screen-but-real elements from `visit_descendants`/`find_by_*`
    // (Slint does not walk clipped-away content). Set a generously large
    // window once per harness so no suite has to reason about scroll
    // clipping.
    harness
        .ui
        .window()
        .set_size(slint::LogicalSize::new(1600.0, 1200.0));
    (harness, repo, provider)
}

/// Builds an `AgentModeConfig` with a permanently-elevated
/// `mcp_interaction_count` (an agent write-tool call is "in flight" for the
/// whole scenario, not just a real ~50ms window) and the given granted
/// scopes -- mirrors `controller::sessions`'s own private
/// `tests::agent_mode_fixture` (that module's unit tests cover the pure
/// `agent_mode_execute_blocked` decision in isolation; this one lets the
/// element suites drive the real Reconnect / "Connect in split" call sites
/// end to end against the same scenario).
pub(crate) fn agent_mode_fixture(
    interaction_count: usize,
    read: bool,
    write: bool,
    execute: bool,
) -> cm_ui::AgentModeConfig {
    cm_ui::AgentModeConfig {
        external_port: 0,
        scopes: Arc::new(std::sync::RwLock::new(cm_core::ScopeSet {
            read,
            write,
            execute,
        })),
        mcp_interaction_count: Arc::new(std::sync::atomic::AtomicUsize::new(interaction_count)),
    }
}

/// Finds a single element by its fully-qualified Slint id
/// (`"Component::local-name"`, e.g. `"QuickConnectForm::qc-host-field"`).
/// Panics with every id actually present in the resting tree if it isn't
/// found -- the single most useful debugging aid for "the dialog wasn't open
/// / the kind wasn't switched yet, so this element doesn't exist" mistakes:
/// elements behind `if` conditions in `.slint` must be driven into existence
/// (open the dialog, switch the kind) before a query can find them --
/// `visit_descendants` (and every `find_by_*` built on it) only ever walks
/// the *resting* tree, never elements that could exist under some other
/// state.
pub(crate) fn find_by_id(root: &impl ElementRoot, id: &str) -> ElementHandle {
    if let Some(e) = ElementHandle::find_by_element_id(root, id).next() {
        return e;
    }
    panic!(
        "find_by_id({id:?}): no such element in the current tree (dialog not open, or wrong \
         per-kind state driven yet?). Known element ids in the resting tree: {:?}",
        all_ids(root)
    );
}

/// Like [`find_by_id`], but asserts there is at most one match and returns
/// `None` rather than panicking when there are zero -- for manifest checks
/// that want to assert a field's *absence* under some kind/state (e.g. "the
/// Domain field does not exist for an SSH quick-connect").
pub(crate) fn find_by_id_opt(root: &impl ElementRoot, id: &str) -> Option<ElementHandle> {
    let mut matches = ElementHandle::find_by_element_id(root, id);
    let first = matches.next();
    assert!(
        matches.next().is_none(),
        "find_by_id_opt({id:?}): more than one match in the current tree"
    );
    first
}

/// Finds the single descendant of `scope` whose `accessible-label` equals
/// `label`. For disambiguating repeated components that share one
/// compiler-assigned id -- e.g. every `SegmentedControl` option shares the id
/// `"SegmentedControl::seg-tab"` (the contract's "repeated instances
/// disambiguate via item-index, never label suffixes" rule), and the app has
/// more than one `SegmentedControl` with the same option labels ("SSH"/
/// "RDP"/"Local" appears in both the quick-connect dialog and the profile
/// editor). Scoping the search to the one dialog you care about (via
/// [`find_singleton`] or [`find_by_id`]) before matching on label is how you
/// reach the right one.
pub(crate) fn find_descendant_by_label(scope: &ElementHandle, label: &str) -> ElementHandle {
    let label_owned = label.to_string();
    scope
        .query_descendants()
        .match_predicate(move |e| e.accessible_label().as_deref() == Some(label_owned.as_str()))
        .find_first()
        .unwrap_or_else(|| {
            panic!("find_descendant_by_label({label:?}): no matching descendant in scope")
        })
}

/// Like [`find_descendant_by_label`], but returns `None` rather than
/// panicking when there is no match -- for asserting a labeled descendant's
/// *absence* (e.g. "no selectable mode named X exists in this scope").
pub(crate) fn find_descendant_by_label_opt(
    scope: &ElementHandle,
    label: &str,
) -> Option<ElementHandle> {
    let label_owned = label.to_string();
    scope
        .query_descendants()
        .match_predicate(move |e| e.accessible_label().as_deref() == Some(label_owned.as_str()))
        .find_first()
}

/// The single instance of a component type in the whole window. Panics if
/// there are zero or more than one -- every dialog root / top-level
/// singleton this harness looks up (`QuickConnectForm`, `ProfileEditor`,
/// `CommandPalette`, ...) is mounted exactly once in `app.slint`; only their
/// *contents* are conditionally instantiated, never the root itself (Modal
/// toggles `visible`, not existence).
pub(crate) fn find_singleton(root: &impl ElementRoot, type_name: &str) -> ElementHandle {
    let mut matches = ElementHandle::find_by_element_type_name(root, type_name);
    let first = matches.next().unwrap_or_else(|| {
        panic!("find_singleton({type_name:?}): no element of this type in the tree")
    });
    assert!(
        matches.next().is_none(),
        "find_singleton({type_name:?}): more than one match -- use a scoped query instead"
    );
    first
}

/// Finds the element with qualified id `id` (repeated-item ids are shared by
/// every instance -- see [`find_descendant_by_label`]'s doc) whose
/// `accessible-item-index` equals `item_index`. For repeated rows/tabs/
/// options where the label isn't unique either (e.g. two tabs opened with the
/// same title), index is the only reliable disambiguator -- and it is
/// literally what the a11y contract puts there for exactly this purpose.
pub(crate) fn nth_by_id(root: &impl ElementRoot, id: &str, item_index: usize) -> ElementHandle {
    ElementQuery::from_root(root)
        .match_id(id)
        .match_predicate(move |e| e.accessible_item_index() == Some(item_index))
        .find_first()
        .unwrap_or_else(|| {
            panic!(
                "nth_by_id({id:?}, {item_index}): no match (only found: {:?})",
                {
                    let mut idxs: Vec<_> = ElementHandle::find_by_element_id(root, id)
                        .filter_map(|e| e.accessible_item_index())
                        .collect();
                    idxs.sort_unstable();
                    idxs
                }
            )
        })
}

fn all_ids(root: &impl ElementRoot) -> Vec<String> {
    let mut ids = Vec::new();
    root.root_element().visit_descendants(|e: ElementHandle| {
        if let Some(id) = e.id() {
            ids.push(id.to_string());
        }
        ControlFlow::<()>::Continue(())
    });
    ids.sort();
    ids.dedup();
    ids
}

/// Advances mock time in [`REDRAW_TICK`]-sized steps (the real redraw
/// timer's cadence) until `predicate` holds or `max_ticks` is exhausted.
/// Returns whether it succeeded -- callers assert on the result with a
/// message naming what they were waiting for. Zero real sleeping: this is
/// what makes `suite_overlays.rs`'s scenarios complete in wall-clock
/// milliseconds rather than seconds of real waiting, and is the "N
/// mock-ticks" bound the task spec asks for (never an unbounded loop).
pub(crate) fn pump_until(max_ticks: u32, mut predicate: impl FnMut() -> bool) -> bool {
    if predicate() {
        return true;
    }
    for _ in 0..max_ticks {
        i_slint_backend_testing::mock_elapsed_time(REDRAW_TICK);
        if predicate() {
            return true;
        }
    }
    false
}

/// Advances mock time by exactly `ticks` redraw intervals, unconditionally --
/// for scenarios asserting something did NOT happen ("the connecting overlay
/// holds indefinitely") rather than polling for something that should.
pub(crate) fn pump_ticks(ticks: u32) {
    for _ in 0..ticks {
        i_slint_backend_testing::mock_elapsed_time(REDRAW_TICK);
    }
}
