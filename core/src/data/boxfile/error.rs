//! Errors which can occur while creating, parsing or transforming a `boxfile`

use std::{io, path::PathBuf};

use crate::encryption::CryptoError;

/// Everything which can go wrong with a `boxfile`, from the file it is built out of to the
/// serialized form it is stored as
#[derive(Debug, thiserror::Error)]
pub enum BoxfileError {
    /// The target file already carries a `.box` extension, so there is nothing to box
    #[error("'{0}' is already boxed (has a .box extension)")]
    AlreadyBoxed(PathBuf),
    /// The file is shorter than the magic and version it would have to start with
    #[error("'{0}' is too small to be a boxfile")]
    TooSmall(PathBuf),
    /// The file does not start with the `boxfile` magic
    #[error("'{0}' is not a valid boxfile")]
    NotBoxfile(PathBuf),
    #[error("unable to encode {what}")]
    Encode {
        what: &'static str,
        #[source] source: bincode::error::EncodeError
    },
    #[error("unable to decode {what}")]
    Decode {
        what: &'static str,
        #[source] source: bincode::error::DecodeError
    },
    /// The header claims more padding than the body can hold, so the original data cannot be cut
    /// back out of it
    #[error("the recorded padding length ({padding}) exceeds the boxfile body ({body} bytes)")]
    InvalidPadding { body: usize, padding: u16 },
    #[error("unable to encrypt the boxfile")]
    Encryption(#[source] CryptoError),
    #[error("unable to decrypt the boxfile")]
    Decryption(#[source] CryptoError),
    #[error("unable to access '{path}'")]
    Io {
        path: PathBuf,
        #[source] source: io::Error
    },
}

impl BoxfileError {
    /// Builds an [`BoxfileError::Io`] for the given path. Shorthand for the `map_err` which every
    /// filesystem call in this module needs
    pub fn io(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        move |source| BoxfileError::Io { path: path.into(), source }
    }
}
