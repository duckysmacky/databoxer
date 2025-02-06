//! Contains the core functionality of the program and main subcommand logic

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use crate::core::data::{io, keys};
use crate::core::encryption::boxfile;
use crate::{log_debug, log_info, log_warn, new_err, Result};
pub mod utils;
pub mod error;
pub mod data;
pub mod encryption;
pub mod profile;
pub mod key;
pub mod options;

/// Encrypts the file at provided path using current profile's key. Password is required to verify
/// and get access to current profile. Additional options can be supplied to change the encryption
/// process
pub fn encrypt(
        input_path: &Path,
        password: &str,
        keep_original_name: bool,
        output_paths: &mut Option<VecDeque<PathBuf>>,
) -> Result<()> {
    log_info!("Starting encryption...");
    if let Some(extension) = input_path.extension() {
        if extension == "box" {
            return Err(new_err!(InvalidInput: InvalidFile, "Already encrypted"))
        }
    }

    let mut boxfile = boxfile::Boxfile::new(input_path)?;
    let key = keys::get_key(password)?;
    boxfile.encrypt_data(&key)?;

    let mut output_path = match output_paths {
        Some(ref mut paths) => {
            if let Some(mut path) = paths.pop_front() {
                log_debug!("Writing to custom output path: {:?}", path);

                if path.file_name() == None {
                    path.set_file_name(uuid::Uuid::new_v4().to_string());
                }
                path
            } else {
                input_path.to_path_buf()
            }
        },
        None => input_path.to_path_buf()
    };
    
    if !keep_original_name {
        output_path.set_file_name(uuid::Uuid::new_v4().to_string());
    }

    output_path.set_extension("box");
    boxfile.save_to(&output_path)?;
    fs::remove_file(&input_path)?;

    Ok(())
}

/// Decryption the file at provided path using current profile's key. Password is required to
/// verify and get access to current profile. Additional options can be supplied to change the
/// decryption process
pub fn decrypt(
    input_path: &Path,
    password: &str,
    output_paths: &mut Option<VecDeque<PathBuf>>,
) -> Result<()> {
    log_info!("Starting decryption...");
    let mut boxfile = boxfile::Boxfile::parse(&input_path)?;
    let key = keys::get_key(password)?;
    boxfile.decrypt_data(&key)?;
    let (original_name, original_extension) = boxfile.file_info();
    let file_data = boxfile.file_data()?;

    log_info!("Validating checksum...");
    if boxfile.verify_checksum()? {
        log_info!("Checksum verification successful");
    } else {
        log_warn!("Checksum verification failed. Data seems to be tampered with");
    }

    let output_path = match output_paths {
        Some(ref mut paths) => {
            if let Some(mut path) = paths.pop_front() {
                log_debug!("Writing to custom output path: {:?}", path);

                if path.file_name() == None {
                    path.set_file_name(original_name);
                    if let Some(extension) = original_extension {
                        path.set_extension(extension);
                    }
                } else if path.extension() == None {
                    if let Some(extension) = original_extension {
                        path.set_extension(extension);
                    }
                }
                path
            } else {
                let mut path = input_path.to_path_buf();
                path.set_file_name(original_name);
                if let Some(extension) = original_extension {
                    path.set_extension(extension);
                }
                path
            }
        },
        None => {
            let mut path = input_path.to_path_buf();
            path.set_file_name(original_name);
            if let Some(extension) = original_extension {
                path.set_extension(extension);
            }
            path
        }
    };
    
    io::write_bytes(&output_path, &file_data, true)?;
    fs::remove_file(&input_path)?;

    Ok(())
}