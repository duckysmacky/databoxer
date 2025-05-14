//! Contains the core functionality of the program and main subcommand logic

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use chrono::{DateTime, Local};
use encryption::boxfile::EncryptedField;
use crate::core::data::{io, keys};
use crate::core::encryption::boxfile;
use crate::{log, new_err, Result};
pub mod utils;
pub mod error;
pub mod data;
pub mod encryption;
pub mod profile;
pub mod key;
pub mod options;
pub mod logs;
mod prompt;
mod os;

/// Encrypts the file at provided path using current profile's key. Password is required to verify
/// and get access to current profile. Additional options can be supplied to change the encryption
/// process
pub fn encrypt(
    input_path: &Path,
    password: &Option<&String>,
    keep_original_name: bool,
    generate_padding: bool,
    encrypt_metadata: bool,
    output_paths: &mut Option<VecDeque<PathBuf>>,
) -> Result<()> {
    log!(INFO, "Starting encryption...");
    if let Some(extension) = input_path.extension() {
        if extension == "box" {
            return Err(new_err!(InvalidInput: InvalidFile, "Already encrypted"))
        }
    }

    let mut boxfile = boxfile::Boxfile::new(input_path, generate_padding, encrypt_metadata)?;
    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    let key = keys::get_key(&password)?;
    boxfile.encrypt_data(&key)?;

    let output_path = match output_paths {
        Some(ref mut paths) => {
            if let Some(mut output) = paths.pop_front() {
                log!(DEBUG, "Writing to custom output path: {:?}", output);
                
                if let Some(file_name) = output.file_name() {
                    output.set_file_name(file_name.to_string_lossy().to_string());
                } else if output.is_file() {
                    output.set_file_name(uuid::Uuid::new_v4().to_string());
                }
                
                output
            } else {
                let mut output = input_path.to_path_buf();
                if !keep_original_name {
                    output.set_file_name(uuid::Uuid::new_v4().to_string());
                }
                output.set_extension("box");
                output
            }
        },
        None => {
            let mut output = input_path.to_path_buf();
            if !keep_original_name {
                output.set_file_name(uuid::Uuid::new_v4().to_string());
            }
            output.set_extension("box");
            output
        }
    };

    boxfile.save_to(&output_path)?;
    fs::remove_file(&input_path)?;

    Ok(())
}

/// Decryption the file at provided path using current profile's key. Password is required to
/// verify and get access to current profile. Additional options can be supplied to change the
/// decryption process
pub fn decrypt(
    input_path: &Path,
    password: &Option<&String>,
    output_paths: &mut Option<VecDeque<PathBuf>>,
) -> Result<()> {
    log!(INFO, "Starting decryption...");
    let mut boxfile = boxfile::Boxfile::parse(&input_path)?;
    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    let key = keys::get_key(&password)?;
    boxfile.decrypt_data(&key)?;
    let (original_name, original_extension) = boxfile.file_info();
    let file_data = boxfile.file_data()?;

    log!(INFO, "Validating checksum...");
    if boxfile.verify_checksum()? {
        log!(INFO, "Checksum verification successful");
    } else {
        log!(WARN, "Checksum verification failed. Data seems to be tampered with");
    }

    let output_path = match output_paths {
        Some(ref mut paths) => {
            if let Some(mut output) = paths.pop_front() {
                log!(DEBUG, "Writing to custom output path: {:?}", output);
                
                if let Some(file_name) = output.file_name() {
                    output.set_file_name(file_name.to_string_lossy().to_string());
                } else if output.is_file() {
                    if let Some(name) = original_name {
                        output.set_file_name(name);
                    }
                    if let Some(extension) = original_extension {
                        output.set_extension(extension);
                    }
                }

                output
            } else {
                let mut path = input_path.to_path_buf();
                
                if let Some(name) = original_name {
                    path.set_file_name(name);
                } else {
                    log!(WARN, "Original file name is unknown");
                    path.set_file_name(uuid::Uuid::new_v4().to_string());
                }
                
                if let Some(extension) = original_extension {
                    path.set_extension(extension);
                } else {
                    log!(WARN, "Original file extension is unknown or missing");
                }
                
                path
            }
        },
        None => {
            let mut path = input_path.to_path_buf();
            
            if let Some(name) = original_name {
                path.set_file_name(name);
            } else {
                log!(WARN, "Original file name is unknown");
                path.set_file_name(uuid::Uuid::new_v4().to_string());
            }
            
            if let Some(extension) = original_extension {
                path.set_extension(extension);
            } else {
                log!(WARN, "Original file extension is unknown or missing");
            }
            
            path
        }
    };
    
    io::write_bytes(&output_path, &file_data, true)?;
    fs::remove_file(&input_path)?;

    Ok(())
}

/// Parses the provided boxfile and retrieves original metadata from the header. Returns a vector
/// containing string with retrieved information, skipping the unknown metadata unless specified
/// not to
pub fn get_info(
    input_path: &Path,
    show_unknown: bool
) -> Result<Vec<String>> {
    fn format_time(system_time: SystemTime) -> String {
        let time: DateTime<Local> = system_time.into();
        format!("{}", time.format("%d.%m.%Y %T"))
    }

    log!(INFO, "Getting file information...");
    let boxfile = boxfile::Boxfile::parse(&input_path)?;
    let header = boxfile.header;

    let mut file_info = Vec::new();

    if header.encrypt_original_data {
        file_info.push("Original file data seems to be encrypted. Unavailable to retrieve file information!".to_string());   
    }

    if let EncryptedField::Plaintext(name) = header.name {
        file_info.push(format!("Name: {:?}", name));
    } else {
        file_info.push("Name: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(extension) = header.extension {
        file_info.push(format!("Extension: {:?}", extension));
    } else {
        file_info.push("Extension: None".to_string());
    }

    if let EncryptedField::Plaintext(source_os) = header.source_os {
        file_info.push(format!("OS: {:?}", source_os));
    } else {
        file_info.push("OS: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(system_time) = header.create_time {
        file_info.push(format!("Create time: {}", format_time(system_time)));
    } else if show_unknown {
        file_info.push("Create time: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(system_time) = header.modify_time {
        file_info.push(format!("Modify time: {}", format_time(system_time)));
    } else if show_unknown {
        file_info.push("Modify time: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(system_time) = header.access_time {
        file_info.push(format!("Access time: {}", format_time(system_time)));
    } else if show_unknown {
        file_info.push("Access time: Unknown".to_string());
    }

    Ok(file_info)
}
