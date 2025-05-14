//! Provides structs which hold optional parameters for the API functions for easier option supply

use std::{collections::VecDeque, path::PathBuf};

pub struct EncryptionOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
    /// Don't replace the name with a random UUID for the encrypted file
    pub keep_original_name: bool,
    /// Generate random padding bytes and append them to the file. If set
    /// to false, can save some disk space for the file
    pub generate_padding: bool,
    /// Whether to encrypt original file metadata like file name, extension, modify time, etc. 
    /// Enabling this feature provides better data protection, but the file will be unable to parse
    /// from the outside without properly decrypting (e.g. encrypted file search by its original
    /// name will be unavailable)
    pub encrypt_metadata: bool,
    /// Contains an output path for each file
    pub output_paths: Option<VecDeque<PathBuf>>
}

impl Default for EncryptionOptions<'_> {
    fn default() -> Self {
        EncryptionOptions {
            password: None,
            keep_original_name: false,
            generate_padding: true,
            encrypt_metadata: false,
            output_paths: None,
        }
    }
}

pub struct DecryptionOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
    /// Contains an output path for each file
    pub output_paths: Option<VecDeque<PathBuf>>
}

impl Default for DecryptionOptions<'_> {
    fn default() -> Self {
        DecryptionOptions {
            password: None,
            output_paths: None,
        }
    }
}

pub struct InformationOptions {
    /// Show unknown metadata with the rest
    pub show_unknown: bool,
}

impl Default for InformationOptions {
    fn default() -> Self {
        InformationOptions {
            show_unknown: false,
        }
    }
}

pub struct ProfileCreateOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
}

impl Default for ProfileCreateOptions<'_> {
    fn default() -> Self {
        ProfileCreateOptions {
            password: None,
        }
    }
}

pub struct ProfileDeleteOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
}

impl Default for ProfileDeleteOptions<'_> {
    fn default() -> Self {
        ProfileDeleteOptions {
            password: None,
        }
    }
}

pub struct ProfileSelectOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
}

impl Default for ProfileSelectOptions<'_> {
    fn default() -> Self {
        ProfileSelectOptions {
            password: None,
        }
    }
}

pub struct KeyNewOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
}

impl Default for KeyNewOptions<'_> {
    fn default() -> Self {
        KeyNewOptions {
            password: None,
        }
    }
}

pub struct KeyGetOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
    /// Format encryption key as list of bytes
    pub as_byte_array: bool
}

impl Default for KeyGetOptions<'_> {
    fn default() -> Self {
        KeyGetOptions {
            password: None,
            as_byte_array: false,
        }
    }
}

pub struct KeySetOptions<'a> {
    /// Pre-supplied password for authentication
    pub password: Option<&'a String>,
}

impl Default for KeySetOptions<'_> {
    fn default() -> Self {
        KeySetOptions {
            password: None,
        }
    }
}
