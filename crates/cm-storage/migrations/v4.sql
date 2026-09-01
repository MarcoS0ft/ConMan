-- v4: CredentialSource on connections.
--
-- Connection.credential: Option<CredentialId> became
-- Connection.credential_source: Option<CredentialSource>
-- ({ Object(CredentialId), Inline{username,domain,has_secret}, Prompt }).
-- `cred_source_kind` is the discriminant ('inherit'|'object'|'inline'|
-- 'prompt'); the existing `credential_id` column keeps holding the Object
-- id (used iff cred_source_kind='object'). Inline usernames/domains/the
-- has-secret flag are non-secret metadata -- the inline secret itself lives
-- only in the keychain (CredentialRef::for_connection), never in this row.
--
-- Back-fill preserves today's behavior exactly: every existing row already
-- has NULL/non-NULL `credential_id` meaning "inherit"/"explicit object" --
-- the UPDATE below just makes that meaning explicit via the new
-- discriminant. Rows with credential_id NULL stay 'inherit' (the column
-- default), matching the pre-v4 "None = inherit" semantics exactly.

ALTER TABLE connections ADD COLUMN cred_source_kind  TEXT    NOT NULL DEFAULT 'inherit';
ALTER TABLE connections ADD COLUMN inline_username   TEXT;
ALTER TABLE connections ADD COLUMN inline_domain     TEXT;
ALTER TABLE connections ADD COLUMN inline_has_secret INTEGER NOT NULL DEFAULT 0;

UPDATE connections SET cred_source_kind = 'object' WHERE credential_id IS NOT NULL;
