pub mod download;
pub mod embed;
pub mod registry;

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("checksum mismatch for {what}: expected {expected}, got {got}")]
    Checksum { what: String, expected: String, got: String },
    #[error("model not found: {0}")]
    UnknownModel(String),
    #[error("download cancelled by the user")]
    Cancelled,
    #[error("embedding backend: {0}")]
    Backend(String),
}
