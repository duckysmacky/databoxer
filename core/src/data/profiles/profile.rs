use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    data::auth,
    encryption::cipher,
    Key, Nonce,
};
use super::ProfileError;


/// Struct containing main information about a profile
#[derive(Serialize, Deserialize, Debug)]
pub struct Profile {
    /// Name of the profile
    pub name: String,
    /// Profile's password stored in a hashed form
    password_hash: String,
    /// Per-profile nonce used to perform encryption operations on profile's key
    nonce: Nonce,
    /// Profile's encryption key stored in an encrypted format
    key: Vec<u8>,
    /// List of files associated with the profile
    #[serde(default)]
    associated_files: Vec<PathBuf>,
}

impl Profile {
    pub fn new(
        name: &str,
        password: &str
    ) -> Result<Self, ProfileError> {
        let (password_hash, password_key) = auth::hash_password(password)?;
        let key = cipher::generate_key();
        let nonce = cipher::generate_nonce();
        let encrypted_key = cipher::encrypt(&password_key, &nonce, &key)
            .map_err(ProfileError::KeyEncryption)?;

        Ok(Profile {
            name: name.to_string(),
            key: encrypted_key,
            nonce,
            password_hash,
            associated_files: Vec::new(),
        })
    }

    /// Checks whether the provided password is valid for the profile by verifying it with the hash
    pub fn verify_password(&self, password: &str) -> Result<(), ProfileError> {
        auth::verify_password(&self.password_hash, password).map(|_| ())
    }

    /// Sets a new key for the profile. Encrypts provided Key based on password and saves it to the
    /// profile in the encrypted form
    pub fn set_key(&mut self, password: &str, key: Key) -> Result<(), ProfileError> {
        let password_key = auth::get_password_key(&self.password_hash, password)?;
        let encrypted_key = cipher::encrypt(&password_key, &self.nonce, &key)
            .map_err(ProfileError::KeyEncryption)?;

        self.key = encrypted_key;
        Ok(())
    }

    /// Fetches encryption key for the current profile. Decrypts contained key based on the password
    /// after verifying it and returns it
    pub fn get_key(&self, password: &str) -> Result<Key, ProfileError> {
        let encrypted_key = self.key.clone();
        let password_key = auth::get_password_key(&self.password_hash, password)?;
        let decrypted = cipher::decrypt(&password_key, &self.nonce, &encrypted_key)
            .map_err(ProfileError::KeyDecryption)?;

        let length = decrypted.len();
        let key = decrypted.try_into()
            .map_err(|_| ProfileError::InvalidKeyLength(length))?;

        Ok(key)
    }
    
    /// Specify a file which is associated with the profile
    pub fn add_associated_file(&mut self, file: &Path) {
        self.associated_files.push(file.to_path_buf());
    }

    /// Remove a file from being associated with the profile
    pub fn remove_associated_file(&mut self, file: &Path) {
        self.associated_files.retain(|f| f != file);
    }
    
    /// Get a list of all files associated with the profile
    pub fn get_associated_files(&self) -> &Vec<PathBuf> {
        &self.associated_files
    }
}
