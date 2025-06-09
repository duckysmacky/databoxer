use std::path::{Path, PathBuf};
use std::collections::VecDeque;
use std::fs;
use crate::core::data::{keys, boxfile::Boxfile};
use crate::core::prompt;
use crate::{log, new_err};

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
) -> crate::Result<()> {
    log!(INFO, "Starting encryption...");
    if let Some(extension) = input_path.extension() {
        if extension == "box" {
            return Err(new_err!(InvalidInput: InvalidFile, "Already encrypted"))
        }
    }

    let mut boxfile = Boxfile::new(input_path, generate_padding, encrypt_metadata)?;
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