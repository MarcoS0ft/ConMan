use slint::VecModel;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use super::PendingUiAction;
use crate::ToastEntry;
use cm_core::application::{
    Application, BootstrapDto, GatewayPreferences, RequestId, WorkspaceDto, WorkspaceMutation,
    WorkspaceRevision,
};
use cm_core::{ConnectionId, CredentialFolderId, GroupId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EditorKind {
    Profile,
    Group,
    Credential,
    CredentialFolder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EditorCorrelation {
    pub kind: EditorKind,
    pub instance: u64,
    pub edit_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EditorState {
    pub instance: u64,
    pub edit_generation: u64,
    pub pending: Option<RequestId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrderedMove {
    Connection {
        id: ConnectionId,
        group_id: Option<GroupId>,
        sort: i64,
    },
    Group {
        id: GroupId,
        parent_id: Option<GroupId>,
        sort: i64,
    },
    CredentialFolder {
        id: CredentialFolderId,
        parent_id: Option<CredentialFolderId>,
        sort: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrderKind {
    Connections,
    Groups,
    CredentialFolders,
}

impl OrderedMove {
    pub(crate) fn into_mutation(self) -> WorkspaceMutation {
        match self {
            Self::Connection { id, group_id, sort } => {
                WorkspaceMutation::MoveConnection { id, group_id, sort }
            }
            Self::Group {
                id,
                parent_id,
                sort,
            } => WorkspaceMutation::MoveGroup {
                id,
                parent_id,
                sort,
            },
            Self::CredentialFolder {
                id,
                parent_id,
                sort,
            } => WorkspaceMutation::MoveCredentialFolder {
                id,
                parent_id,
                sort,
            },
        }
    }
}

pub(crate) struct WorkspaceReorderPlan {
    pub generation: u64,
    pub kind: OrderKind,
    pub changes: Vec<OrderedMove>,
    pub next_index: usize,
}

pub(crate) struct UiState {
    pub application: Rc<dyn Application>,
    pub toast_model: Rc<VecModel<ToastEntry>>,
    pub toast_next_id: i32,
    pub bootstrap: Option<BootstrapDto>,
    pub workspace: Option<WorkspaceDto>,
    pub revision: Option<WorkspaceRevision>,
    pub preferences: Option<GatewayPreferences>,
    pub pending: HashMap<RequestId, PendingUiAction>,
    pub committed_editor: Option<super::CommittedEditor>,
    pub refresh_required: bool,
    pub next_editor_instance: u64,
    pub profile_editor: Option<EditorState>,
    pub group_editor: Option<EditorState>,
    pub credential_editor: Option<EditorState>,
    pub credential_folder_editor: Option<EditorState>,
    pub preference_generation: u64,
    pub preferences_in_flight: Option<(RequestId, u64)>,
    pub desired_preferences: Option<GatewayPreferences>,
    pub next_order_plan_generation: u64,
    pub ordering_plan: Option<WorkspaceReorderPlan>,
}

pub(crate) type SharedUiState = Rc<RefCell<UiState>>;

impl UiState {
    pub(super) fn new(
        application: Rc<dyn Application>,
        toast_model: Rc<VecModel<ToastEntry>>,
    ) -> Self {
        Self {
            application,
            toast_model,
            toast_next_id: 1,
            bootstrap: None,
            workspace: None,
            revision: None,
            preferences: None,
            pending: HashMap::new(),
            committed_editor: None,
            refresh_required: false,
            next_editor_instance: 0,
            profile_editor: None,
            group_editor: None,
            credential_editor: None,
            credential_folder_editor: None,
            preference_generation: 0,
            preferences_in_flight: None,
            desired_preferences: None,
            next_order_plan_generation: 0,
            ordering_plan: None,
        }
    }
}

impl UiState {
    pub(super) fn editor_instance(&mut self) -> u64 {
        self.next_editor_instance = self.next_editor_instance.wrapping_add(1).max(1);
        self.next_editor_instance
    }

    pub(super) fn open_editor(&mut self, kind: EditorKind) -> EditorCorrelation {
        let instance = self.editor_instance();
        let editor = EditorState {
            instance,
            edit_generation: 0,
            pending: None,
        };
        *self.editor_mut(kind) = Some(editor);
        EditorCorrelation {
            kind,
            instance,
            edit_generation: 0,
        }
    }

    pub(super) fn editor_mut(&mut self, kind: EditorKind) -> &mut Option<EditorState> {
        match kind {
            EditorKind::Profile => &mut self.profile_editor,
            EditorKind::Group => &mut self.group_editor,
            EditorKind::Credential => &mut self.credential_editor,
            EditorKind::CredentialFolder => &mut self.credential_folder_editor,
        }
    }

    pub(super) fn editor(&self, kind: EditorKind) -> Option<EditorState> {
        match kind {
            EditorKind::Profile => self.profile_editor,
            EditorKind::Group => self.group_editor,
            EditorKind::Credential => self.credential_editor,
            EditorKind::CredentialFolder => self.credential_folder_editor,
        }
    }
}
