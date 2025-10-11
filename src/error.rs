use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetToolsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("System error: {0}")]
    Nix(#[from] nix::errno::Errno),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Name too long: {0}")]
    NameTooLong(String),

    #[error("Protocol family not supported")]
    ProtocolNotSupported,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NetToolsError>;
