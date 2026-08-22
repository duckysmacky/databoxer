//! Contains functions related to user authentication and password

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{Salt, SaltString};
use crate::{Result, new_err, Key};

/// Hashes the given password. Returns hashed password and key generated based on the password hash
/// used to encrypt the stored encryption key
pub fn hash_password(password: &str) -> Result<(String, Key)> {
    let salt = SaltString::generate(&mut OsRng);
    let mut password_key = Key::default();

    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|err| new_err!(CryptoError: Hash, "Profile password".to_string(); err))?.to_string();
    argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut password_key)
        .map_err(|err| new_err!(CryptoError: Hash, "Key from profile password".to_string(); err))?;
    Ok((password_hash, password_key))
}

/// Verifies password by comparing it to the password hash, returning password hash's Salt 
/// if the verification is successful. Errors if the Salt is missing
// TODO: refactor to return a bool instead of relaying on Result
pub fn verify_password<'a>(password_hash: &'a str, password: &str) -> Result<Salt<'a>> {
    let hash = PasswordHash::new(password_hash)
        .map_err(|_| new_err!(InvalidData: InvalidLength, "Password hash".to_string()))?;

    let argon2 = Argon2::default();
    argon2.verify_password(password.as_bytes(), &hash)
        .map_err(|_| new_err!(ProfileError: AuthenticationFailed))?;
    
    let salt = hash.salt
        .ok_or_else(|| new_err!(InvalidData: MissingData, "Salt for the password hash".to_string()))?;
    Ok(salt)
}

/// Returns the encryption key generated based on the password if the password verification is
/// successful
pub fn get_password_key(password_hash: &str, password: &str) -> Result<Key> {
    let salt = verify_password(password_hash, password)?;
    let mut password_key = Key::default();
    
    let argon2 = Argon2::default();
    argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut password_key)
        .map_err(|err| new_err!(CryptoError: Hash, "Key from profile password".to_string(); err))?;
    Ok(password_key)
}

#[cfg(test)]
mod tests {
    use crate::encryption::cipher;
    use super::*;

    #[test]
    fn test_password_hash() -> Result<()> {
        let password = "my_password123";
        let (hash, _) = hash_password(password)?;
        
        assert!(verify_password(&hash, password).is_ok());
        Ok(())
    }
    
    #[test]
    fn test_password_key() -> Result<()> {
        let password = "my_password123";
        let text = "Hello, world!";
        let nonce = cipher::generate_nonce();
        
        // Encrypt text with original password key
        let (hash, key) = hash_password(password)?;
        let encrypted_text = cipher::encrypt(&key, &nonce, text.as_bytes())?;
        
        // Decrypt text with retrieved password key after verifying it
        let key = get_password_key(&hash, password)?;
        let decrypted_bytes = cipher::decrypt(&key, &nonce, &encrypted_text)?;
        let decrypted_text = String::from_utf8_lossy(&decrypted_bytes);
        
        assert_eq!(decrypted_text, text);
        Ok(())
    }
}