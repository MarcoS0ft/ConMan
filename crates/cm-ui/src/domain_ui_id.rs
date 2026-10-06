//! Lossless conversion for signed-i64 entity IDs crossing the Slint boundary.
//!
//! Empty text is the UI sentinel for an unsaved entity or absent relationship.
//! Persisted IDs use canonical decimal text; zero remains Core's UNSAVED value
//! and is never accepted as a persisted identity.

use cm_core::{ConnectionId, CredentialFolderId, CredentialId, GroupId};
use slint::SharedString;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainIdError {
    Empty,
    Invalid,
    NonCanonical,
    ReservedZero,
}

impl fmt::Display for DomainIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "entity ID is empty",
            Self::Invalid => "entity ID is not a signed 64-bit integer",
            Self::NonCanonical => "entity ID is not canonical decimal text",
            Self::ReservedZero => "zero is reserved for an unsaved entity",
        })
    }
}

impl std::error::Error for DomainIdError {}

fn parse_value(text: &str) -> Result<i64, DomainIdError> {
    if text.is_empty() {
        return Err(DomainIdError::Empty);
    }
    let value = text.parse::<i64>().map_err(|_| DomainIdError::Invalid)?;
    if value.to_string() != text {
        return Err(DomainIdError::NonCanonical);
    }
    if value == 0 {
        return Err(DomainIdError::ReservedZero);
    }
    Ok(value)
}

macro_rules! id_conversions {
    ($text:ident, $parse:ident, $form:ident, $optional:ident, $id:ty) => {
        pub(crate) fn $text(id: $id) -> SharedString {
            if id.get() == 0 {
                SharedString::default()
            } else {
                SharedString::from(id.get().to_string())
            }
        }

        pub(crate) fn $parse(text: &str) -> Result<$id, DomainIdError> {
            parse_value(text).map(<$id>::new)
        }

        #[allow(dead_code)]
        pub(crate) fn $form(text: &str) -> Result<$id, DomainIdError> {
            if text.is_empty() {
                Ok(<$id>::UNSAVED)
            } else {
                $parse(text)
            }
        }

        #[allow(dead_code)]
        pub(crate) fn $optional(text: &str) -> Result<Option<$id>, DomainIdError> {
            if text.is_empty() {
                Ok(None)
            } else {
                $parse(text).map(Some)
            }
        }
    };
}

id_conversions!(
    connection_id_text,
    parse_connection_id,
    parse_connection_form_id,
    parse_optional_connection_id,
    ConnectionId
);
id_conversions!(
    group_id_text,
    parse_group_id,
    parse_group_form_id,
    parse_optional_group_id,
    GroupId
);
id_conversions!(
    credential_id_text,
    parse_credential_id,
    parse_credential_form_id,
    parse_optional_credential_id,
    CredentialId
);
id_conversions!(
    credential_folder_id_text,
    parse_credential_folder_id,
    parse_credential_folder_form_id,
    parse_optional_credential_folder_id,
    CredentialFolderId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_id_type_round_trips_signed_i64_boundaries_and_collisions() {
        let values = [i64::MAX, i64::MIN, -1, 1, 4_294_967_297];
        for value in values {
            let connection = ConnectionId::new(value);
            assert_eq!(
                parse_connection_id(&connection_id_text(connection)).unwrap(),
                connection
            );
            let group = GroupId::new(value);
            assert_eq!(parse_group_id(&group_id_text(group)).unwrap(), group);
            let credential = CredentialId::new(value);
            assert_eq!(
                parse_credential_id(&credential_id_text(credential)).unwrap(),
                credential
            );
            let folder = CredentialFolderId::new(value);
            assert_eq!(
                parse_credential_folder_id(&credential_folder_id_text(folder)).unwrap(),
                folder
            );
        }
        assert_eq!(1_i64 & 0xffff_ffff, 4_294_967_297_i64 & 0xffff_ffff);
    }

    #[test]
    fn empty_is_contextual_and_invalid_nonempty_values_fail_closed() {
        assert_eq!(connection_id_text(ConnectionId::UNSAVED).as_str(), "");
        assert_eq!(group_id_text(GroupId::UNSAVED).as_str(), "");
        assert_eq!(credential_id_text(CredentialId::UNSAVED).as_str(), "");
        assert_eq!(
            credential_folder_id_text(CredentialFolderId::UNSAVED).as_str(),
            ""
        );
        assert_eq!(parse_connection_form_id(""), Ok(ConnectionId::UNSAVED));
        assert_eq!(parse_optional_group_id(""), Ok(None));
        assert_eq!(
            parse_credential_form_id("0"),
            Err(DomainIdError::ReservedZero)
        );
        for text in [
            "+1",
            "01",
            "-0",
            " 1",
            "1 ",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert!(parse_connection_id(text).is_err(), "accepted {text:?}");
        }
        assert_eq!(parse_connection_id(""), Err(DomainIdError::Empty));
        assert_eq!(
            parse_credential_folder_id("nope"),
            Err(DomainIdError::Invalid)
        );
    }
}
