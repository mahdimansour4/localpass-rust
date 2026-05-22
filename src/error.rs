pub type Result<T> = std::result::Result<T, LocalPassError>;

#[derive(Debug, thiserror::Error)]
pub enum LocalPassError {
    #[error("vault already exists")]
    VaultAlreadyExists,

    #[error("vault not found")]
    VaultNotFound,

    #[error("invalid vault file")]
    InvalidVaultFile,

    #[error("failed to unlock vault")]
    UnlockFailed,

    #[error("entry not found: {0}")]
    EntryNotFound(String),

    #[error("entry already exists: {0}")]
    DuplicateEntry(String),

    #[error("invalid password generator options")]
    InvalidGeneratorOptions,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Message(String),
}
