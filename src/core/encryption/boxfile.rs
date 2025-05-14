//! Contains implementation for the custom `boxfile` file format, it's header and
//! additional information for parsing and serializing the custom file format.

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::{fs, iter};
use std::time::SystemTime;
use crate::{log, new_err, Checksum, Key, Nonce, Result};
use crate::core::data::io;
use crate::core::os::OS;
use crate::core::utils;
use super::cipher;

mod header_info {
    //! Constants for the header: current file format version and unique file
    //! identifier (magic)
    /// Unique identifier for the `boxfile` file format
    pub const MAGIC: [u8; 3] = [b'B', b'O', b'X'];
    /// The current version of the `boxfile` format being used for backwards compatibility
    pub const CURRENT_VERSION: u8 = 1;
}

/// Struct representing a `boxfile` structure. A "boxfile" is the custom file 
/// format for databoxer which contains the encrypted data of a file, alongside
/// header with extra information and random padding. It is generated as a result
/// of file encryption operation and has a `.box` extension.
///
/// *The `boxfile` structure is heavily inspired by the SSH Packet structure, as it
/// is known to be safe and efficient*
#[derive(Serialize, Deserialize)]
pub struct Boxfile {
    /// Custom header for the boxfile. Not encrypted unlike the body of the file and
    /// is available for reading by other processing, meaning an encryption key is
    /// not required, as doesn't contain any sensitive information.
    ///
    /// *Could be a subject to change in the future*
    pub header: BoxfileHeader,
    /// File body is the encrypted content of the original file together with randomly
    /// generated `padding`. It is the main payload for the entire `boxfile`. Can be
    /// compressed for reduced storage size
    ///
    /// `Padding` is a randomly generated array of random bytes used for encryption
    /// obfuscation. It is encrypted together with the original file so that bytes
    /// mix together and make information even more unreadable without a decryption
    /// key. There must be at least 4 bytes of padding and a maximum of 255 bytes.
    ///
    /// Padding should be of such a length, that the total length of any `boxfile`
    /// component (header/body/padding itself) is a multiple of the cipher block
    /// size or 8 (whichever is larger).
    body: Box<[u8]>,
    /// Checksum is a hash generated from the content of the `boxfile` file body
    /// before the encryption occurs. It ensures the data's integrity by comparing
    /// it to the checksum generated after decryption of the same file.
    checksum: Checksum,
}

impl Boxfile {
    /// Generates a new `boxfile` from the provided file. Creates a new `BoxfileHeader`
    /// and stores original file's name and extension in it, also generates a unique 
    /// `Nonce` for later usage in encryption. Padding is also generated during this
    /// step and added at the end of the original file's data as a part of the body.
    /// Checksum is generated at the very end from the header and body content.
    pub fn new(file_path: &Path, generate_padding: bool, encrypt_header_data: bool) -> Result<Self> {
        log!(DEBUG, "Initializing boxfile from {:?}", file_path);
        let file_data = io::read_bytes(&file_path)?;
        let mut padding_len = 0;
        let body: Box<[u8]> = match generate_padding {
            true => {
                let padding = Self::generate_padding(file_data.len(), 512);
                padding_len = padding.len() as u16;
                [file_data, padding].concat().into()
            },
            false => file_data.into()
        };
        log!(DEBUG, "Boxfile body generated");

        let header = BoxfileHeader::new(
            file_path,
            padding_len,
            cipher::generate_nonce(),
            encrypt_header_data,
        )?;
        log!(DEBUG, "Boxfile header generated: {:?}", &header);

        let mut hasher = Sha256::new();
        hasher.update(&header.as_bytes()?);
        hasher.update(&body);
        let result = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&result);
        log!(DEBUG, "Checksum generated: {:?}", utils::hex::bytes_to_string(&checksum));

        Ok(Self {
            header,
            body,
            checksum
        })
    }

    /// Parses the provided file, tries to deserialize it and returns a parsed `boxfile`.
    pub fn parse(file_path: &Path) -> Result<Self> {
        log!(DEBUG, "Parsing boxfile from {:?}", file_path);

        if let Some(extension) = file_path.extension() {
            if extension != "box" {
                log!(WARN, "Target file extension is not '.box'");
            }
        }

        let bytes = io::read_bytes(file_path)?;
        if bytes.len() < 4 {
            return Err(new_err!(InvalidInput: InvalidFile, "Too small to be parsed correctly"))
        }
        
        let magic = &bytes[..3];
        if magic != &header_info::MAGIC[..3] {
            return Err(new_err!(InvalidInput: InvalidFile, "Not a valid boxfile"))
        }
        
        let version = &bytes[3];
        if version != &header_info::CURRENT_VERSION {
            log!(WARN, "Target file uses a different boxfile version");
        }

        // TODO: add custom configuration options
        let config = bincode::config::standard();
        let (boxfile, _bytes): (Boxfile, usize) = bincode::serde::decode_from_slice(&bytes, config)
            .map_err(|err| new_err!(SerializeError: BoxfileParseError, err))?;

        log!(DEBUG, "Boxfile deserialized");
        Ok(boxfile)
    }

    /// Returns the information about the file contained within the `boxfile`: original file name, 
    /// and extension
    pub fn file_info(&self) -> (Option<&String>, Option<&String>) {
        let name = match &self.header.name {
            EncryptedField::Plaintext(value) => Some(value),
            _ => None,
        };
        let extension = match &self.header.extension {
            EncryptedField::Plaintext(value) => Some(value),
            _ => None,
        };
        (name, extension)
    }
    
    /// Verifies checksum for the `boxfile` by generating new checksum for current data and
    /// comparing it to the checksum stored in the header
    pub fn verify_checksum(&self) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(&self.header.as_bytes()?);
        hasher.update(&self.body);

        let result = hasher.finalize();
        let mut checksum = [0u8; 32];

        checksum.copy_from_slice(&result);
        log!(DEBUG, "Boxfile checksum: {:?}", utils::hex::bytes_to_string(&self.checksum));
        log!(DEBUG, "Updated checksum: {:?}", utils::hex::bytes_to_string(&checksum));
        Ok(checksum == self.checksum)
    }

    /// Serializes self and writes to specified file
    pub fn save_to(&self, path: &Path) -> Result<()> {
        log!(DEBUG, "Serializing and saving boxfile to {:?}", path);

        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&self, config)
            .map_err(|err| new_err!(SerializeError: BoxfileParseError, err))?;
        io::write_bytes(path, &bytes, true)?;

        Ok(())
    }

    /// Encrypts the body of the `boxfile` together with randomly generated padding 
    /// using the provided encryption key
    pub fn encrypt_data(&mut self, key: &Key) -> Result<()> {
        log!(DEBUG, "Encrypting boxfile");

        let encrypted_body = cipher::encrypt(key, &self.header.nonce, &self.body)?;
        self.body = encrypted_body.into();

        if self.header.encrypt_original_data {
            self.header.encrypt_data(key)?;
        }

        Ok(())
    }
    
    /// Decrypts the body of the `boxfile` (data + padding) using the provided encryption key
    pub fn decrypt_data(&mut self, key: &Key) -> Result<()> {
        log!(DEBUG, "Decrypting boxfile");

        let decrypted_body = cipher::decrypt(key, &self.header.nonce, &self.body)?;
        self.body = decrypted_body.into();

        if self.header.encrypt_original_data {
            self.header.decrypt_data(key)?;
        }

        Ok(())
    }

    /// Removes the generated padding, returning only the actual data content of the original file
    pub fn file_data(&self) -> Result<Box<[u8]>> {
        log!(DEBUG, "Retrieving file data from boxfile");
        let padding_len = self.header.padding_len;
        let data_len = self.body.len() as i32 - padding_len as i32;
        if data_len < 0 {
            return Err(new_err!(SerializeError: BoxfileParseError, "Invalid file data length"))
        }
        let file_data = &self.body[..data_len as usize];
        Ok(file_data.into())
    }

    /// Generates padding to append to the end of body before encryption according
    /// to the PKCS standard algorithm: adds random padding bytes to fill out the block
    /// size for the file data
    fn generate_padding(data_len: usize, block_size: usize) -> Vec<u8> {
        let padding_len = block_size - (data_len % block_size);
        let mut rng = rand::rng();
        let padding = iter::repeat_with(|| rng.random::<u8>())
            .take(padding_len)
            .collect::<Vec<u8>>();
        padding
    }
}

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
    padding_len: u16,
    /// Randomly generated 12-byte `Nonce` used for encryption and decryption. Ensures
    /// that no ciphertext generated using one key is the same
    nonce: Nonce,
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
    ) -> Result<Self> {
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
            magic: header_info::MAGIC,
            version: header_info::CURRENT_VERSION,
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
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        log!(DEBUG, "Serializing Boxfile header");

        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&self, config)?;

        log!(DEBUG, "Boxfile header successfully serialized");
        Ok(bytes)
    }

    /// Encrypts the file's original data within the header (file name, extension, etc.)
    /// using the provided encryption key
    pub fn encrypt_data(&mut self, key: &Key) -> Result<()> {
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
    pub fn decrypt_data(&mut self, key: &Key) -> Result<()> {
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
    pub fn encrypt(&mut self, encrypt_function: impl Fn(&[u8]) -> Result<Vec<u8>>) -> Result<()> {
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
    pub fn decrypt(&mut self, decrypt_function: impl Fn(&[u8]) -> Result<Vec<u8>>) -> Result<()> {
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
