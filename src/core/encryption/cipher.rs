//! Contains methods related to encryption and decryption, key and nonce generation

use chacha20poly1305::{
    aead::{OsRng, Aead, KeyInit},
    AeadCore, ChaCha20Poly1305
};
use crate::{log, new_err, Result};

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

/// Encrypts and returns encrypted bytes with ChaCha20Ply1305 algorithm using provided `Key` and
/// `Nonce`
pub fn encrypt(key: &Key, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
    log!(DEBUG, "Encrypting bytes");
    let cipher = ChaCha20Poly1305::new(key.into());

    let ciphertext = cipher.encrypt(nonce.into(), data)
        .map_err(|err| new_err!(EncryptionError: CipherError, err))?;
    Ok(ciphertext)
}

/// Decrypts and returns decrypted bytes with ChaCha20Ply1305 algorithm using provided `Key` and
/// `Nonce`. Provided `Key` and `Nonce` should match the ones which were used to encrypt file for
/// successful decryption
pub fn decrypt(key: &Key, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
    log!(DEBUG, "Decrypting bytes");
    let cipher = ChaCha20Poly1305::new(key.into());

    let plaintext = cipher.decrypt(nonce.into(), data)
        .map_err(|err| new_err!(EncryptionError: CipherError, err))?;
    Ok(plaintext)
}
