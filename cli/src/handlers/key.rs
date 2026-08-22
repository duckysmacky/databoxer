//! Handlers for the `databoxer key` command and its subcommands

use std::fs::File;
use std::io::Read;
use clap::ArgMatches;
use databoxer_core::error;
use databoxer_core::{options, log};
use crate::output;

/// Handles the `databoxer key new` subcommand. Returns an exit code indicating the status of the
/// operation (0 for success, non-zero for errors).
pub fn handle_key_new(args: &ArgMatches) -> i32 {
    let mut options = options::KeyNewOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    let mut exit_code = 0;
    
    match databoxer_core::new_key(options) {
        Ok(_) => log!(SUCCESS, "Successfully generated new encryption key for the current profile"),
        Err(err) => {
            log!(ERROR, "Unable to generate a new encryption key ({})", err.name());
            exit_code = err.exit_code() as i32;
            
            if handle_error(err) {
                return exit_code;
            }
        }
    }
    
    exit_code
}

/// Handles the `databoxer key get` subcommand. Returns an exit code indicating the status of the
/// operation (0 for success, non-zero for errors).
pub fn handle_key_get(args: &ArgMatches) -> i32 {
    let mut options = options::KeyGetOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    options.as_byte_array = args.get_flag("AS_BYTE_ARRAY");
    
    let mut exit_code = 0;
    
    match databoxer_core::get_key(options) {
        Ok(key) => {
            // TODO: add current profile name
            log!(SUCCESS, "Encryption key for the current profile:");
            output!("{}", key);
        }
        Err(err) => {
            log!(ERROR, "Unable to get an encryption key for the current profile ({})", err.name());
            exit_code = err.exit_code() as i32;

            if handle_error(err) {
                return exit_code;
            }
        }
    }
    
    exit_code
}

/// Handles the `databoxer key set` subcommand. Returns an exit code indicating the status of the
/// operation (0 for success, non-zero for errors).
pub fn handle_key_set<'a>(args: &ArgMatches) -> i32 {
    let new_key = {
        if let Some(key_path) = args.get_one::<String>("FILE") {
            get_key_from_file(key_path).unwrap_or_else(|err| {
                log!(ERROR, "Unable to read the key file: {}", err);
                std::process::exit(1)
            })
        } else {
            args.get_one::<String>("KEY").expect("Key is required").to_string()
        }
    };

    let mut options = options::KeySetOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    let mut exit_code = 0;
    
    match databoxer_core::set_key(&new_key, options) {
        Ok(_) => log!(SUCCESS, "Successfully set a new encryption key for the current profile"),
        Err(err) => {
            log!(ERROR, "Unable to set an encryption key for the current profile ({})", err.name());
            exit_code = err.exit_code() as i32;

            if handle_error(err) {
                return exit_code;
            }
        }
    }
    
    exit_code
}

fn get_key_from_file<'a>(key_path: &String) -> std::io::Result<String> {
    let mut file = File::open(key_path)?;
    let mut buffer = vec![0u8; 64];
    file.read_exact(&mut buffer)?;

    String::from_utf8(buffer)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
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
        _ => true,
    }
}