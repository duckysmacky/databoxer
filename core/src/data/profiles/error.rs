//! Errors which can occur while managing user profiles and the data they are stored in

use std::{io, path::PathBuf};

use crate::encryption::CryptoError;

/// Everything which can go wrong with a user profile, from the state it is in to the file the
/// profiles are kept in
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("profile '{0}' not found")]
    NotFound(String),
    #[error("no profile is currently selected")]
    NotSelected,
    #[error("profile '{0}' is already selected")]
    AlreadySelected(String),
    #[error("profile '{0}' already exists")]
    AlreadyExists(String),
    /// The supplied password does not match the profile's stored hash
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("unable to hash the profile password")]
    Hashing(#[source] argon2::password_hash::Error),
    /// Deriving the key which the profile's encryption key is stored under failed
    #[error("unable to derive a key from the profile password")]
    KeyDerivation(#[source] argon2::Error),
    #[error("the profile's stored password hash is malformed")]
    MalformedHash(#[source] argon2::password_hash::Error),
    #[error("the profile's stored password hash carries no salt")]
    MissingSalt,
    #[error("unable to encrypt the profile's encryption key")]
    KeyEncryption(#[source] CryptoError),
    /// The password is verified before the stored key is touched, so reaching this means the
    /// stored data itself is broken rather than the password being wrong
    #[error("unable to decrypt the profile's encryption key - the profile data may be corrupt")]
    KeyDecryption(#[source] CryptoError),
    #[error("the profile's stored encryption key is {0} bytes long, expected 32")]
    InvalidKeyLength(usize),
    #[error("unable to parse the profile data at '{path}'")]
    Deserialize {
        path: PathBuf,
        #[source] source: serde_json::Error
    },
    #[error("unable to serialize the profile data")]
    Serialize(#[from] serde_json::Error),
    #[error("unable to access the profile data at '{path}'")]
    Io {
        path: PathBuf,
        #[source] source: io::Error
    },
    #[error("unable to locate the profile data directory")]
    DataDir(#[source] io::Error),
}

impl ProfileError {
    /// Builds a [`ProfileError::Io`] for the given path. Shorthand for the `map_err` which the
    /// profile file operations need
    pub fn io(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        move |source| ProfileError::Io { path: path.into(), source }
    }
}
