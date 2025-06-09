use std::path::Path;
use std::fs;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use crate::core::data::boxfile::info;
use crate::core::os::OS;
use crate::{log, Key, Nonce};
use crate::core::encryption::cipher;

/// The header for the `boxfile`, which contains extra information about the file. This
/// includes a unique identifier (magic), length of the generated padding, the original
/// file name and extension and generated `Nonce` for encryption/decryption uniqueness
#[derive(Serialize, Deserialize, Debug)]
pub struct BoxfileHeader {
    /// Unique identifier for the file format
    magic: [u8; 3],
    /// Version of the current file format protocol being used
    pub version: u8,
    /// The length of the generated padding
    pub padding_len: u16,
    /// Randomly generated 12-byte `Nonce` used for encryption and decryption. Ensures
    /// that no ciphertext generated using one key is the same
    pub nonce: Nonce,
    /// The original name of the file
    #[serde(default)]
    pub name: EncryptedField<String>,
    /// The operating system on which the file was encrypted
    #[serde(default)]
    pub source_os: EncryptedField<OS>,
    /// The original extension of the file
    #[serde(default)]
    pub extension: EncryptedField<String>,
    /// The original create time of the file
    #[serde(default)]
    pub create_time: EncryptedField<SystemTime>,
    /// The original modify time of the file
    #[serde(default)]
    pub modify_time: EncryptedField<SystemTime>,
    /// The original access time of the file
    #[serde(default)]
    pub access_time: EncryptedField<SystemTime>,
    /// Is the original file data (name, extension, etc.) is encrypted. If so, file
    /// cannot be pre-parsed without decryption.
    pub encrypt_original_data: bool,
}

impl BoxfileHeader {
    pub fn new(
        file_path: &Path,
        padding_len: u16,
        nonce: Nonce,
        encrypt_original_data: bool
    ) -> crate::Result<Self> {
        let os = OS::get();
        let name = file_path.file_stem().map(|name| {
            name.to_os_string().into_string().unwrap_or_else(|name| {
                log!(WARN, "Unable to properly convert file name to local os");
                name.to_string_lossy().to_string()
            })
        });
        let extension = file_path.extension().map(|ext| {
            ext.to_os_string().into_string().unwrap_or_else(|ext| {
                log!(WARN, "Unable to properly convert file extension to local os");
                ext.to_string_lossy().to_string()
            })
        });
        let metadata = fs::metadata(file_path).map_err(|err| {
            log!(WARN, "Unable to get metadata of file: {}", err);
        });
        let create_time = match &metadata {
            Ok(data) => data.created().ok(),
            Err(_) => None,
        };
        let modify_time = match &metadata {
            Ok(data) => data.modified().ok(),
            Err(_) => None,
        };
        let access_time = match &metadata {
            Ok(data) => data.accessed().ok(),
            Err(_) => None,
        };

        Ok(BoxfileHeader {
            magic: info::MAGIC,
            version: info::CURRENT_VERSION,
            encrypt_original_data,
            name: name.into(),
            source_os: EncryptedField::Plaintext(os),
            extension: extension.into(),
            create_time: create_time.into(),
            modify_time: modify_time.into(),
            access_time: access_time.into(),
            padding_len,
            nonce
        })
    }

    /// Returns the header serialized as plain bytes
    pub fn as_bytes(&self) -> crate::Result<Vec<u8>> {
        log!(DEBUG, "Serializing Boxfile header");

        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&self, config)?;

        log!(DEBUG, "Boxfile header successfully serialized");
        Ok(bytes)
    }

    /// Encrypts the file's original data within the header (file name, extension, etc.)
    /// using the provided encryption key
    pub fn encrypt_data(&mut self, key: &Key) -> crate::Result<()> {
        log!(DEBUG, "Encrypting header data");

        // this function is used for encryption within the inner wrapper to avoid boilerplate. same
        // with decryption
        let func = |data: &[u8]| cipher::encrypt(key, &self.nonce, data);

        if self.encrypt_original_data {
            self.name.encrypt(func)?;
            self.source_os.encrypt(func)?;
            self.extension.encrypt(func)?;
            self.create_time.encrypt(func)?;
            self.modify_time.encrypt(func)?;
            self.access_time.encrypt(func)?;
        }
        Ok(())
    }

    /// Decrypts the file's original data using the provided encryption key
    pub fn decrypt_data(&mut self, key: &Key) -> crate::Result<()> {
        log!(DEBUG, "Decrypting header data");

        let func = |data: &[u8]| cipher::decrypt(key, &self.nonce, data);

        if self.encrypt_original_data {
            self.name.decrypt(func)?;
            self.source_os.decrypt(func)?;
            self.extension.decrypt(func)?;
            self.create_time.decrypt(func)?;
            self.modify_time.decrypt(func)?;
            self.access_time.decrypt(func)?;
        }
        Ok(())
    }
}

/// Enum representing a field in the `BoxfileHeader` which can be encrypted. Can contain plaintext
/// (not encrypted) data, encrypted data and an empty value (in case if field can be `None` to
/// avoid extra encryption). Only `Plaintext` values should be interacted with, while everything
/// else to be considered non-relevant for outside interaction
#[derive(Serialize, Deserialize, Debug)]
pub enum EncryptedField<T> {
    Empty,
    Plaintext(T),
    Encrypted(Box<[u8]>),
}

impl<T> EncryptedField<T>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>
{
    /// Encrypts the field value and stores it as an array of bytes within itself. Accepts an
    /// encryption function to operate on data. This is made to reduce the amount of repeating
    /// argument passing from one field to the other.
    pub fn encrypt(&mut self, encrypt_function: impl Fn(&[u8]) -> crate::Result<Vec<u8>>) -> crate::Result<()> {
        if let EncryptedField::Plaintext(data) = self {
            let config = bincode::config::standard();
            let bytes = bincode::serde::encode_to_vec(data, config)?;
            let encrypted = encrypt_function(&bytes)?;
            *self = EncryptedField::Encrypted(encrypted.into());
        }
        Ok(())
    }

    /// Decrypts the field value and restores the original data type `T` within itself. Accepts a
    /// decryption function to operate on data. This is made to reduce the amount of repeating
    /// argument passing from one field to the other.
    pub fn decrypt(&mut self, decrypt_function: impl Fn(&[u8]) -> crate::Result<Vec<u8>>) -> crate::Result<()> {
        if let EncryptedField::Encrypted(encrypted) = self {
            let decrypted = decrypt_function(&encrypted)?;
            let config = bincode::config::standard();
            let (data, _): (T, usize) = bincode::serde::decode_from_slice(&decrypted, config)?;
            *self = EncryptedField::Plaintext(data);
        }
        Ok(())
    }

    /// Returns whether the field is empty (is an `Empty` value). Used together with serde to skip
    /// empty field values to save disk space
    pub fn is_empty(&self) -> bool {
        matches!(self, EncryptedField::Empty)
    }
}

/// Automatically convert from `Option<T>` to `Plaintext(T)` is there is `Some(value)`, else will
/// covert to `Empty`
impl<T> From<Option<T>> for EncryptedField<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => EncryptedField::Plaintext(v),
            None => EncryptedField::Empty,
        }
    }
}

impl<T> Default for EncryptedField<T> {
    fn default() -> Self {
        EncryptedField::Empty
    }
}