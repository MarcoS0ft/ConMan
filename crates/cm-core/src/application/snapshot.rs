//! Incremental, capacity-accounted assembly of a persisted workspace snapshot.
use std::mem::size_of;

use super::{
    AppEvent, Capability, Credential, CredentialFolder, Group, ResultClass, SessionDto,
    SubmitError, WorkspaceDto, WorkspaceRevision, add_cap, add_connection, add_credential,
    add_folder, add_group, add_vec,
};

pub const MAX_WORKSPACE_RECORDS: usize = 4_096;
/// Maximum transient allocation allowance for one typed settings decode.
pub const MAX_WORKSPACE_ROW_DECODE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceRecordCounts {
    pub connections: usize,
    pub groups: usize,
    pub credentials: usize,
    pub credential_folders: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum WorkspaceResultOverhead<'a> {
    Workspace,
    Bootstrap {
        capabilities: &'a Vec<Capability>,
        sessions: &'a Vec<SessionDto>,
    },
}

#[derive(Debug, Clone, Copy)]
enum RecordKind {
    Connection,
    Group,
    Credential,
    Folder,
}

/// Owns the partially built snapshot and its allocation meter. A failed
/// build can only be dropped; `finish` is the sole operation that exposes it.
#[derive(Debug)]
pub struct WorkspaceSnapshotBuilder<'a> {
    workspace: WorkspaceDto,
    expected: WorkspaceRecordCounts,
    bytes_used: usize,
    overhead: WorkspaceResultOverhead<'a>,
    decode_active: bool,
}

impl<'a> WorkspaceSnapshotBuilder<'a> {
    pub fn new(
        revision: WorkspaceRevision,
        row_counts: WorkspaceRecordCounts,
        overhead: WorkspaceResultOverhead<'a>,
    ) -> Result<Self, SubmitError> {
        if [
            row_counts.connections,
            row_counts.groups,
            row_counts.credentials,
            row_counts.credential_folders,
        ]
        .into_iter()
        .any(|count| count > MAX_WORKSPACE_RECORDS)
        {
            return Err(SubmitError::ResourceLimit);
        }

        let mut workspace = WorkspaceDto {
            revision,
            connections: Vec::new(),
            groups: Vec::new(),
            credentials: Vec::new(),
            credential_folders: Vec::new(),
        };
        workspace
            .connections
            .try_reserve_exact(row_counts.connections)
            .map_err(|_| SubmitError::ResourceLimit)?;
        workspace
            .groups
            .try_reserve_exact(row_counts.groups)
            .map_err(|_| SubmitError::ResourceLimit)?;
        workspace
            .credentials
            .try_reserve_exact(row_counts.credentials)
            .map_err(|_| SubmitError::ResourceLimit)?;
        workspace
            .credential_folders
            .try_reserve_exact(row_counts.credential_folders)
            .map_err(|_| SubmitError::ResourceLimit)?;

        let mut bytes_used = size_of::<AppEvent>();
        add_vec(&mut bytes_used, &workspace.connections)?;
        add_vec(&mut bytes_used, &workspace.groups)?;
        add_vec(&mut bytes_used, &workspace.credentials)?;
        add_vec(&mut bytes_used, &workspace.credential_folders)?;
        if let WorkspaceResultOverhead::Bootstrap {
            capabilities,
            sessions,
        } = overhead
        {
            add_vec(&mut bytes_used, capabilities)?;
            add_vec(&mut bytes_used, sessions)?;
        }
        if bytes_used > ResultClass::Workspace.limit() {
            return Err(SubmitError::ResourceLimit);
        }

        Ok(Self {
            workspace,
            expected: row_counts,
            bytes_used,
            overhead,
            decode_active: false,
        })
    }

    /// Reserve transient decoder memory and worst-case result headroom before
    /// constructing the typed Connection. The permit exclusively borrows this
    /// builder until it is committed or dropped.
    pub fn reserve_connection_decode(
        &mut self,
        scratch_bytes: usize,
        destination_upper_bound: usize,
    ) -> Result<RowDecodePermit<'_, 'a>, SubmitError> {
        self.reserve(
            RecordKind::Connection,
            scratch_bytes,
            destination_upper_bound,
        )
    }

    pub fn reserve_group(
        &mut self,
        destination_upper_bound: usize,
    ) -> Result<RowDecodePermit<'_, 'a>, SubmitError> {
        self.reserve(RecordKind::Group, 0, destination_upper_bound)
    }

    pub fn reserve_credential(
        &mut self,
        destination_upper_bound: usize,
    ) -> Result<RowDecodePermit<'_, 'a>, SubmitError> {
        self.reserve(RecordKind::Credential, 0, destination_upper_bound)
    }

    pub fn reserve_credential_folder(
        &mut self,
        destination_upper_bound: usize,
    ) -> Result<RowDecodePermit<'_, 'a>, SubmitError> {
        self.reserve(RecordKind::Folder, 0, destination_upper_bound)
    }

    fn reserve(
        &mut self,
        kind: RecordKind,
        scratch_bytes: usize,
        destination_upper_bound: usize,
    ) -> Result<RowDecodePermit<'_, 'a>, SubmitError> {
        if self.decode_active || scratch_bytes > MAX_WORKSPACE_ROW_DECODE_BYTES {
            return Err(SubmitError::ResourceLimit);
        }
        let (len, expected) = match kind {
            RecordKind::Connection => (self.workspace.connections.len(), self.expected.connections),
            RecordKind::Group => (self.workspace.groups.len(), self.expected.groups),
            RecordKind::Credential => (self.workspace.credentials.len(), self.expected.credentials),
            RecordKind::Folder => (
                self.workspace.credential_folders.len(),
                self.expected.credential_folders,
            ),
        };
        if len >= expected
            || self
                .bytes_used
                .checked_add(destination_upper_bound)
                .filter(|bytes| *bytes <= ResultClass::Workspace.limit())
                .is_none()
        {
            return Err(SubmitError::ResourceLimit);
        }
        self.decode_active = true;
        Ok(RowDecodePermit {
            builder: self,
            kind,
            scratch_bytes,
            destination_upper_bound,
            committed: false,
        })
    }

    pub fn finish(self) -> Result<WorkspaceDto, SubmitError> {
        if self.decode_active
            || self.workspace.connections.len() != self.expected.connections
            || self.workspace.groups.len() != self.expected.groups
            || self.workspace.credentials.len() != self.expected.credentials
            || self.workspace.credential_folders.len() != self.expected.credential_folders
        {
            return Err(SubmitError::ResourceLimit);
        }
        // Keep the borrowed overhead alive through finish so the capability
        // and session vectors cannot change after their capacities are charged.
        let _overhead = self.overhead;
        if self.bytes_used > ResultClass::Workspace.limit() {
            return Err(SubmitError::ResourceLimit);
        }
        Ok(self.workspace)
    }
}

#[derive(Debug)]
pub struct RowDecodePermit<'b, 'a> {
    builder: &'b mut WorkspaceSnapshotBuilder<'a>,
    kind: RecordKind,
    scratch_bytes: usize,
    destination_upper_bound: usize,
    committed: bool,
}

impl RowDecodePermit<'_, '_> {
    pub const fn scratch_bytes(&self) -> usize {
        self.scratch_bytes
    }

    pub fn push_connection(mut self, value: super::Connection) -> Result<(), SubmitError> {
        if !matches!(self.kind, RecordKind::Connection) {
            return Err(SubmitError::ResourceLimit);
        }
        let mut row_bytes = 0;
        add_connection(&mut row_bytes, &value)?;
        self.commit_capacity(row_bytes)?;
        self.builder.workspace.connections.push(value);
        self.committed = true;
        Ok(())
    }

    pub fn push_group(mut self, value: Group) -> Result<(), SubmitError> {
        if !matches!(self.kind, RecordKind::Group) {
            return Err(SubmitError::ResourceLimit);
        }
        let mut row_bytes = 0;
        add_group(&mut row_bytes, &value)?;
        self.commit_capacity(row_bytes)?;
        self.builder.workspace.groups.push(value);
        self.committed = true;
        Ok(())
    }

    pub fn push_credential(mut self, value: Credential) -> Result<(), SubmitError> {
        if !matches!(self.kind, RecordKind::Credential) {
            return Err(SubmitError::ResourceLimit);
        }
        let mut row_bytes = 0;
        add_credential(&mut row_bytes, &value)?;
        self.commit_capacity(row_bytes)?;
        self.builder.workspace.credentials.push(value);
        self.committed = true;
        Ok(())
    }

    pub fn push_credential_folder(mut self, value: CredentialFolder) -> Result<(), SubmitError> {
        if !matches!(self.kind, RecordKind::Folder) {
            return Err(SubmitError::ResourceLimit);
        }
        let mut row_bytes = 0;
        add_folder(&mut row_bytes, &value)?;
        self.commit_capacity(row_bytes)?;
        self.builder.workspace.credential_folders.push(value);
        self.committed = true;
        Ok(())
    }

    fn commit_capacity(&mut self, row_bytes: usize) -> Result<(), SubmitError> {
        if row_bytes > self.destination_upper_bound {
            return Err(SubmitError::ResourceLimit);
        }
        add_cap(&mut self.builder.bytes_used, row_bytes)?;
        if self.builder.bytes_used > ResultClass::Workspace.limit() {
            return Err(SubmitError::ResourceLimit);
        }
        Ok(())
    }
}

impl Drop for RowDecodePermit<'_, '_> {
    fn drop(&mut self) {
        self.builder.decode_active = false;
        // Keep the reservation explicit in this value for diagnostics/tests;
        // the exclusive borrow makes double reservation impossible.
        let _ = self.scratch_bytes;
        let _ = self.committed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConnectionId, ConnectionKind, ConnectionSettings, CredentialPurpose, CredentialRef,
        CredentialSource, GroupId, LocalSettings, SshAuthMethod, SshSettings, WorkspaceRevision,
    };

    fn counts(
        connections: usize,
        groups: usize,
        credentials: usize,
        folders: usize,
    ) -> WorkspaceRecordCounts {
        WorkspaceRecordCounts {
            connections,
            groups,
            credentials,
            credential_folders: folders,
        }
    }

    fn ssh_connection(name_capacity: usize) -> super::super::Connection {
        let mut name = String::new();
        name.try_reserve_exact(name_capacity).unwrap();
        name.push('x');
        super::super::Connection::new(
            ConnectionId::new(1),
            Some(GroupId::new(2)),
            name,
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(SshSettings {
                host: "host".into(),
                port: 22,
                username: "user".into(),
                auth_method: SshAuthMethod::PublicKey {
                    key_ref: CredentialRef::new(
                        crate::CredentialId::new(3),
                        CredentialPurpose::SshKey,
                    ),
                },
            }),
            Some(CredentialSource::Prompt),
            0,
            0,
            0,
        )
        .unwrap()
    }

    #[test]
    fn preallocates_and_accounts_actual_top_level_and_bootstrap_capacity() {
        let mut capabilities = Vec::with_capacity(32);
        capabilities.push(Capability::Ssh);
        let sessions = Vec::<SessionDto>::with_capacity(16);
        let builder = WorkspaceSnapshotBuilder::new(
            WorkspaceRevision(4),
            counts(1, 2, 3, 4),
            WorkspaceResultOverhead::Bootstrap {
                capabilities: &capabilities,
                sessions: &sessions,
            },
        )
        .unwrap();
        assert_eq!(builder.workspace.connections.capacity(), 1);
        assert_eq!(builder.workspace.groups.capacity(), 2);
        assert_eq!(builder.workspace.credentials.capacity(), 3);
        assert_eq!(builder.workspace.credential_folders.capacity(), 4);
        assert!(builder.bytes_used >= size_of::<AppEvent>());
        assert!(builder.bytes_used >= 32 * size_of::<Capability>());
        assert!(builder.bytes_used >= 16 * size_of::<SessionDto>());
    }

    #[test]
    fn rejects_excess_counts_and_oversized_reservation_before_row_build() {
        assert_eq!(
            WorkspaceSnapshotBuilder::new(
                WorkspaceRevision(0),
                counts(MAX_WORKSPACE_RECORDS + 1, 0, 0, 0),
                WorkspaceResultOverhead::Workspace,
            )
            .unwrap_err(),
            SubmitError::ResourceLimit
        );
        let mut builder = WorkspaceSnapshotBuilder::new(
            WorkspaceRevision(0),
            counts(1, 0, 0, 0),
            WorkspaceResultOverhead::Workspace,
        )
        .unwrap();
        assert!(matches!(
            builder.reserve_connection_decode(0, ResultClass::Workspace.limit()),
            Err(SubmitError::ResourceLimit)
        ));
        assert!(
            builder
                .reserve_connection_decode(MAX_WORKSPACE_ROW_DECODE_BYTES + 1, 0)
                .is_err()
        );
    }

    #[test]
    fn row_permit_charges_string_and_credential_reference_capacities() {
        let mut builder = WorkspaceSnapshotBuilder::new(
            WorkspaceRevision(7),
            counts(1, 0, 0, 0),
            WorkspaceResultOverhead::Workspace,
        )
        .unwrap();
        let value = ssh_connection(4096);
        let mut actual = 0;
        add_connection(&mut actual, &value).unwrap();
        assert!(actual > value.name.len());
        let before = builder.bytes_used;
        builder
            .reserve_connection_decode(1024, actual)
            .unwrap()
            .push_connection(value)
            .unwrap();
        assert_eq!(builder.bytes_used, before + actual);
        assert_eq!(builder.finish().unwrap().revision, WorkspaceRevision(7));
    }

    #[test]
    fn local_settings_nested_capacities_use_the_shared_meter() {
        let mut arg = String::new();
        arg.try_reserve_exact(2048).unwrap();
        arg.push('a');
        let mut key = String::new();
        key.try_reserve_exact(1024).unwrap();
        key.push('k');
        let mut val = String::new();
        val.try_reserve_exact(1024).unwrap();
        val.push('v');
        let value = ConnectionSettings::Local(LocalSettings {
            program: Some("shell".into()),
            args: vec![arg],
            working_dir: Some("/tmp".into()),
            env: vec![(key, val)],
        });
        let mut bytes = 0;
        super::super::add_connection_settings(&mut bytes, &value).unwrap();
        match value {
            ConnectionSettings::Local(settings) => {
                assert!(bytes >= settings.args.capacity() * size_of::<String>());
                assert!(bytes >= settings.env.capacity() * size_of::<(String, String)>());
                assert!(bytes >= settings.args[0].capacity());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn finish_never_returns_partial_snapshot() {
        let builder = WorkspaceSnapshotBuilder::new(
            WorkspaceRevision(0),
            counts(1, 0, 0, 0),
            WorkspaceResultOverhead::Workspace,
        )
        .unwrap();
        assert_eq!(builder.finish().unwrap_err(), SubmitError::ResourceLimit);
    }
}
