use thiserror::Error;

/// Vault errors. No variant ever carries secrets: passwords, keys,
/// key file contents or decrypted data must never reach a message.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("not a vault file")]
    NotAVaultFile,

    #[error("a file already exists at this path")]
    AlreadyExists,

    #[error("unsupported format version: {found}; update the application")]
    UnsupportedVersion { found: u32 },

    #[error("vault header is malformed")]
    HeaderMalformed,

    #[error("password hint is too long")]
    HintTooLong,

    #[error("this vault requires a key file")]
    KeyfileRequired,

    #[error("key file cannot be read")]
    KeyfileUnreadable,

    /// Deliberately merges "wrong password/key file" and "corrupted file":
    /// AEAD cannot tell them apart, and splitting them would leak whether
    /// the password was correct (no oracle).
    #[error("wrong password or key file, or the file is damaged")]
    InvalidCredentialsOrCorrupt,

    #[error("invalid KDF parameters")]
    InvalidKdfParams,

    /// The (unauthenticated) header of a file being opened asks for more
    /// Argon2 work than the app will spend on an untrusted open.
    /// Distinct from `InvalidKdfParams` so the message names the real cause: a
    /// crafted or foreign vault, not merely out-of-range numbers.
    #[error("this vault's key-derivation cost is too high to open safely (possibly created by another tool or a crafted file)")]
    KdfParamsTooExpensive,

    /// An OS refusal to read or write the file, split out of `Io` because
    /// `std::io::Error::to_string()` is the C library's `strerror` and is
    /// locale-dependent on Linux — a caller that wants to explain this case
    /// (a snap cannot see hidden folders) cannot match on the message text.
    #[error("permission denied for this file")]
    PermissionDenied,

    #[error("io error: {0}")]
    Io(String),

    #[error("database error: {0}")]
    Db(String),

    #[error("no vault is open")]
    NoVaultOpen,

    #[error("sync network error: {0}")]
    SyncNetwork(String),

    #[error("a vault is already open")]
    AlreadyOpen,

    #[error("vault is locked")]
    Locked,

    #[error("this path was not chosen through the app")]
    PathNotAllowed,

    #[error("entry not found")]
    EntryNotFound,

    #[error("folder not found")]
    FolderNotFound,

    #[error("the root folder cannot be renamed, moved, or deleted")]
    CannotModifyRoot,

    #[error("that move would create a circular folder reference")]
    CircularReference,

    #[error("tag not found")]
    TagNotFound,

    #[error("a tag with this name already exists")]
    DuplicateTagName,

    #[error("color must be #RRGGBB")]
    InvalidColor,

    #[error("field template not found")]
    TemplateNotFound,
    #[error("a field template with this name already exists")]
    DuplicateTemplateName,
    #[error("this is a built-in template and cannot be changed or deleted")]
    TemplateProtected,
    #[error("invalid field type")]
    InvalidFieldType,

    #[error("attachment exceeds the 10 MB limit")]
    AttachmentTooLarge,
    #[error("attachment not found")]
    AttachmentNotFound,

    #[error("relation not found")]
    RelationNotFound,
    #[error("this relation already exists")]
    DuplicateRelation,
    #[error("an entry cannot be related to itself")]
    SelfRelation,
    #[error("invalid relation type")]
    InvalidRelationType,

    #[error("invalid search pattern")]
    InvalidRegex,

    #[error("invalid generator options: {0}")]
    GeneratorOptions(String),

    #[error("invalid TOTP secret")]
    TotpParse(String),

    #[error("not a Kokos export, or an unsupported export version")]
    ImportUnsupported,

    #[error("kdbx_too_large")]
    KdbxTooLarge,
    #[error("kdbx_unsupported")]
    KdbxUnsupported,
    #[error("kdbx_corrupt")]
    KdbxCorrupt,
    #[error("kdbx_wrong_password")]
    KdbxWrongPassword,
}

pub type Result<T> = std::result::Result<T, VaultError>;

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::PermissionDenied => VaultError::PermissionDenied,
            _ => VaultError::Io(e.to_string()),
        }
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Db(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_gets_its_own_variant() {
        let e: VaultError = std::io::Error::from(std::io::ErrorKind::PermissionDenied).into();
        assert!(
            matches!(e, VaultError::PermissionDenied),
            "an OS permission refusal must survive as a distinct variant: strerror text is \
             locale-dependent, so callers cannot recover it from Io's message"
        );
    }

    #[test]
    fn other_io_errors_still_collapse_to_io() {
        let e: VaultError = std::io::Error::from(std::io::ErrorKind::NotFound).into();
        assert!(matches!(e, VaultError::Io(_)), "only the permission case is split out");
    }

    #[test]
    fn permission_denied_message_does_not_leak_errno_text() {
        assert_eq!(VaultError::PermissionDenied.to_string(), "permission denied for this file");
    }
}
