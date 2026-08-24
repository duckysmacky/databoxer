//! Contains methods related to encryption and decryption, key and nonce generation

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, ChaCha20Poly1305,
};

use crate::{hex, log};
use super::CryptoError;

/// Type representing a basic 32-byte encryption key
pub type Key = [u8; 32];
/// Type representing a 32-byte checksum hash used to validate data integrity
pub type Checksum = [u8; 32];
/// Type representing a 12-byte nonce used for encryption in combination with an encryption key
pub type Nonce = [u8; 12];

/// Generates a new random 32-byte encryption key
pub fn generate_key() -> Key {
    ChaCha20Poly1305::generate_key(&mut OsRng).into()
}

/// Generates a new random 12-byte encryption nonce
pub fn generate_nonce() -> Nonce {
    ChaCha20Poly1305::generate_nonce(&mut OsRng).into()
}

/// Parses an encryption key from its hex representation (e.g. `"0128AE1005..."`). The input has to
/// decode to exactly 32 bytes for it to be a valid `Key`
pub fn parse_key(hex_key: &str) -> Result<Key, CryptoError> {
    let bytes = hex::string_to_bytes(hex_key).map_err(CryptoError::InvalidKey)?;

    Key::try_from(&bytes[..]).map_err(|_| CryptoError::InvalidKey(
        format!("expected a 32-byte key, got {} bytes", bytes.len())
    ))
}

/// Encrypts and returns encrypted bytes with ChaCha20Ply1305 algorithm using provided `Key` and
/// `Nonce`
pub fn encrypt(key: &Key, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    log!(DEBUG, "Encrypting bytes");
    let cipher = ChaCha20Poly1305::new(key.into());

    let ciphertext = cipher.encrypt(nonce.into(), data)
        .map_err(|_| CryptoError::Cipher)?;
    Ok(ciphertext)
}

/// Decrypts and returns decrypted bytes with ChaCha20Ply1305 algorithm using provided `Key` and
/// `Nonce`. Provided `Key` and `Nonce` should match the ones which were used to encrypt file for
/// successful decryption
pub fn decrypt(key: &Key, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    log!(DEBUG, "Decrypting bytes");
    let cipher = ChaCha20Poly1305::new(key.into());

    let plaintext = cipher.decrypt(nonce.into(), data)
        .map_err(|_| CryptoError::Cipher)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generated key has to survive a round-trip through its hex representation
    #[test]
    fn test_parse_key_roundtrip() -> Result<(), CryptoError> {
        let key = generate_key();
        assert_eq!(parse_key(&hex::bytes_to_string(&key))?, key);
        Ok(())
    }

    #[test]
    fn test_parse_key_rejects_wrong_length() {
        let short = hex::bytes_to_string(&[0u8; 31]);
        let long = hex::bytes_to_string(&[0u8; 33]);

        assert!(parse_key(&short).is_err());
        assert!(parse_key(&long).is_err());
        assert!(parse_key("").is_err());
    }

    #[test]
    fn test_parse_key_rejects_invalid_hex() {
        assert!(parse_key("not a hex key").is_err());
    }
}
