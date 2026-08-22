//! Handler for the the `databoxer box` command

use clap::ArgMatches;
use std::path::PathBuf;
use std::collections::VecDeque;
use std::ffi::OsStr;
use crate::handlers;
use crate::path;
use databoxer_core::error;
use databoxer_core::{options, log};

/// Handles the `databoxer box` subcommand. Returns a tuple containing:
/// - The total number of files processed
/// - The number of successfully encrypted files
/// - The exit code indicating the status of the operation (0 for success, non-zero for errors)
pub fn handle_box(args: &ArgMatches) -> (u32, u32, i32) {
    let file_paths: Vec<PathBuf> = {
        let input_paths = handlers::get_path_vec(args, "PATH").expect("File path is required");
        let recursive = args.get_flag("RECURSIVE");

        path::parse_paths(input_paths, recursive)
    };

    let mut options = options::EncryptionOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    options.keep_original_name = args.get_flag("KEEP_NAME");
    options.generate_padding = !args.get_flag("NO_PADDING");
    options.encrypt_metadata = args.get_flag("ENCRYPT_METADATA");

    if let Some(output_paths) = args.get_many::<String>("OUTPUT") {
        let mut deque = VecDeque::new();
        for p in output_paths {
            deque.push_back(PathBuf::from(p))
        }
        options.output_paths = Some(deque);
    }

    let total_files: u32 = file_paths.len() as u32;
    let mut successful_files: u32 = 0;
    let mut exit_code: i32 = 0;
    
    // encrypt each file and handle errors accordingly
    for path in file_paths {
        let file_name = match args.get_flag("SHOW_FULL_PATH") {
            true => path.as_os_str().to_os_string(),
            false => path.file_name().unwrap_or(OsStr::new("<unknown file name>")).to_os_string()
        };

        log!(STATUS, "Encrypting {:?}...", file_name);
        match databoxer_core::encrypt(path.as_path(), &mut options) {
            Ok(_) => {
                log!(SUCCESS, "Successfully encrypted {:?}", file_name);
                successful_files += 1;
            },
            Err(err) => {
                log!(ERROR, "Unable to encrypt '{}' ({})", file_name.to_string_lossy(), err.name());
                exit_code = err.exit_code() as i32;
                
                if handle_error(err) {
                    return (total_files, successful_files, exit_code);
                }
            }
        }
    }

    (total_files, successful_files, exit_code)
}

/// Handles the error based on its type and logs appropriate messages. If the error is critical, it 
/// returns 'true' to indicate that the process should exit immediately. Otherwise, it returns 
/// 'false', which allows the process to continue or exit gracefully.
fn handle_error(err: error::Error) -> bool {
    log!(ERROR, "{}", err.message());
    
    if let Some(cause) = err.cause() {
        log!(ERROR, "Caused by: {}", cause);
    }
    
    match err.get_type() {
        error::ErrorType::ProfileError(kind) => {
            match kind {
                error::ProfileErrorKind::AuthenticationFailed => {
                    log!(WARN, "Please check your password and try again.");
                    true
                }
                error::ProfileErrorKind::NotSelected => {
                    log!(WARN, "Please select a profile using 'databoxer profile set <name>' command.");
                    true
                }
                _ => true
            }
        }
        error::ErrorType::InvalidData(kind) => {
            match kind {
                error::InvalidDataKind::InvalidFile(_) => false,
                _ => true
            }
        }
        error::ErrorType::IOError(_) => false,
        _ => true,
    }
}