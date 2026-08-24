//! Errors which can occur while encrypting, decrypting or handling encryption keys

/// Errors produced by the cipher primitives
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The cipher refused the operation. Which operation it was is for the caller to report:
    /// `chacha20poly1305` returns an opaque error which carries nothing of its own
    #[error("cipher operation failed")]
    Cipher,
    /// The supplied encryption key could not be read as a 32-byte key
    #[error("invalid encryption key: {0}")]
    InvalidKey(String),
}
