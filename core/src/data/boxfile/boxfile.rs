//! Contains implementation for the custom `boxfile` file format, it's header and
//! additional information for parsing and serializing the custom file format.

use std::{path::Path, time::SystemTime, iter};

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    encryption::cipher,
    io::fs,
    os::OS,
    Checksum, hex, Key, log,
};
use super::{error::BoxfileError, header::BoxfileHeader, info};

/// The original file's information, as recovered from a `boxfile` header. Any field which was
/// never recorded, or which is still encrypted, comes back as `None`
#[derive(Debug)]
pub struct FileMetadata {
    /// Whether the header's original file data is stored encrypted. While true, every other field
    /// here is `None` until the header has been decrypted
    pub metadata_encrypted: bool,
    pub name: Option<String>,
    pub extension: Option<String>,
    pub source_os: Option<OS>,
    pub create_time: Option<SystemTime>,
    pub modify_time: Option<SystemTime>,
    pub access_time: Option<SystemTime>,
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
    pub fn new(
        file_path: &Path,
        generate_padding: bool,
        encrypt_header_data: bool
    ) -> Result<Self, BoxfileError> {
        log!(DEBUG, "Initializing boxfile from {:?}", file_path);

        if let Some(extension) = file_path.extension() {
            if extension == "box" {
                return Err(BoxfileError::AlreadyBoxed(file_path.to_path_buf()));
            }
        }

        let file_data = fs::read_bytes(&file_path).map_err(BoxfileError::io(file_path))?;
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
        );
        log!(DEBUG, "Boxfile header generated: {:?}", &header);

        let mut hasher = Sha256::new();
        hasher.update(&header.as_bytes()?);
        hasher.update(&body);
        let result = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&result);
        log!(DEBUG, "Checksum generated: {:?}", hex::bytes_to_string(&checksum));

        Ok(Self {
            header,
            body,
            checksum
        })
    }

    /// Parses the provided file, tries to deserialize it and returns a parsed `boxfile`.
    pub fn parse(file_path: &Path) -> Result<Self, BoxfileError> {
        log!(DEBUG, "Parsing boxfile from {:?}", file_path);

        if let Some(extension) = file_path.extension() {
            if extension != "box" {
                log!(WARN, "Target file extension is not '.box'");
            }
        }

        let bytes = fs::read_bytes(file_path).map_err(BoxfileError::io(file_path))?;
        if bytes.len() < 4 {
            return Err(BoxfileError::TooSmall(file_path.to_path_buf()))
        }

        let magic = &bytes[..3];
        if magic != &info::MAGIC[..3] {
            return Err(BoxfileError::NotBoxfile(file_path.to_path_buf()))
        }
        
        let version = &bytes[3];
        if version != &info::CURRENT_VERSION {
            log!(WARN, "Target file uses a different boxfile version");
        }

        // TODO: add custom configuration options
        let config = bincode::config::standard();
        let (boxfile, _bytes): (Boxfile, usize) = bincode::serde::decode_from_slice(&bytes, config)
            .map_err(|source| BoxfileError::Decode { what: "the boxfile", source })?;

        log!(DEBUG, "Boxfile deserialized");
        Ok(boxfile)
    }

    /// Returns everything the header records about the original file. Fields which were never
    /// recorded, or which are still encrypted, come back as `None` - decrypt the boxfile first to
    /// read the metadata of a file which was boxed with metadata encryption enabled
    pub fn metadata(&self) -> FileMetadata {
        let header = &self.header;

        FileMetadata {
            metadata_encrypted: header.encrypt_original_data,
            name: header.name.plaintext().cloned(),
            extension: header.extension.plaintext().cloned(),
            source_os: header.source_os.plaintext().copied(),
            create_time: header.create_time.plaintext().copied(),
            modify_time: header.modify_time.plaintext().copied(),
            access_time: header.access_time.plaintext().copied(),
        }
    }
    
    /// Verifies checksum for the `boxfile` by generating new checksum for current data and
    /// comparing it to the checksum stored in the header
    pub fn verify_checksum(&self) -> Result<bool, BoxfileError> {
        let mut hasher = Sha256::new();
        hasher.update(&self.header.as_bytes()?);
        hasher.update(&self.body);

        let result = hasher.finalize();
        let mut checksum = [0u8; 32];

        checksum.copy_from_slice(&result);
        log!(DEBUG, "Boxfile checksum: {:?}", hex::bytes_to_string(&self.checksum));
        log!(DEBUG, "Updated checksum: {:?}", hex::bytes_to_string(&checksum));
        Ok(checksum == self.checksum)
    }

    /// Serializes self and writes it to the specified file. The destination must not already
    /// exist, so that boxing never destroys a file which is already there
    pub fn save_to(&self, path: &Path) -> Result<(), BoxfileError> {
        log!(DEBUG, "Serializing and saving boxfile to {:?}", path);

        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&self, config)
            .map_err(|source| BoxfileError::Encode { what: "the boxfile", source })?;
        fs::write_new_bytes(path, &bytes).map_err(BoxfileError::io(path))?;

        Ok(())
    }

    /// Writes the original file's contents to the specified path. The destination must not already
    /// exist, so that restoring a file never destroys one which is already there
    pub fn restore_to(&self, path: &Path) -> Result<(), BoxfileError> {
        log!(DEBUG, "Restoring original file contents to {:?}", path);

        let file_data = self.file_data()?;
        fs::write_new_bytes(path, &file_data).map_err(BoxfileError::io(path))?;

        Ok(())
    }

    /// Encrypts the body of the `boxfile` together with randomly generated padding 
    /// using the provided encryption key
    pub fn encrypt_data(&mut self, key: &Key) -> Result<(), BoxfileError> {
        log!(DEBUG, "Encrypting boxfile");

        let encrypted_body = cipher::encrypt(key, &self.header.nonce, &self.body)
            .map_err(BoxfileError::Encryption)?;
        self.body = encrypted_body.into();

        if self.header.encrypt_original_data {
            self.header.encrypt_data(key)?;
        }

        Ok(())
    }
    
    /// Decrypts the body of the `boxfile` (data + padding) using the provided encryption key
    pub fn decrypt_data(&mut self, key: &Key) -> Result<(), BoxfileError> {
        log!(DEBUG, "Decrypting boxfile");

        let decrypted_body = cipher::decrypt(key, &self.header.nonce, &self.body)
            .map_err(BoxfileError::Decryption)?;
        self.body = decrypted_body.into();

        if self.header.encrypt_original_data {
            self.header.decrypt_data(key)?;
        }

        Ok(())
    }

    /// Removes the generated padding, returning only the actual data content of the original file
    pub fn file_data(&self) -> Result<Box<[u8]>, BoxfileError> {
        log!(DEBUG, "Retrieving file data from boxfile");
        let padding_len = self.header.padding_len;
        let data_len = self.body.len() as i32 - padding_len as i32;
        if data_len < 0 {
            return Err(BoxfileError::InvalidPadding {
                body: self.body.len(),
                padding: padding_len
            });
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
