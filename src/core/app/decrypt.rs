use std::path::{Path, PathBuf};
use std::collections::VecDeque;
use std::fs;
use crate::core::data::keys;
use crate::core::prompt;
use crate::log;
use crate::utils::io;

/// Decryption the file at provided path using current profile's key. Password is required to
/// verify and get access to current profile. Additional options can be supplied to change the
/// decryption process
pub fn decrypt(
    input_path: &Path,
    password: &Option<&String>,
    output_paths: &mut Option<VecDeque<PathBuf>>,
) -> crate::Result<()> {
    log!(INFO, "Starting decryption...");
    let mut boxfile = crate::Boxfile::parse(&input_path)?;
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