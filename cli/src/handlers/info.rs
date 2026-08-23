//! Handler for the `databoxer info` command

use clap::ArgMatches;
use std::path::PathBuf;
use crate::path;
use databoxer_core::error;
use databoxer_core::{options, log};
use crate::output;

/// Handles the `databoxer info` subcommand. Returns an exit code indicating the status of the 
/// operation (0 for success, non-zero for errors).
pub fn handle_info(args: &ArgMatches) -> i32 {
    let file_path = {
        let path = args.get_one::<String>("PATH").expect("File path is required");
        let paths = path::parse_paths(vec![PathBuf::from(path)], false);

        if paths.is_empty() {
            std::process::exit(1);
        } else {
            paths[0].clone()
        }
    };

    let mut options = options::InformationOptions::default();
    options.show_unknown = args.get_flag("SHOW_UNKNOWN");

    let mut exit_code = 0;
    
    output!(STATUS, "Retrieving information about '{}'...", file_path.display());
    match databoxer_core::get_info(&file_path, options) {
        Ok(info_lines) => {
            output!(SUCCESS, "Displaying information about '{}':", file_path.display());
            
            for line in info_lines {
                output!(DATA, "{}", line);
            }
        }
        Err(err) => {
            log!(ERROR, "Unable to get information about '{}' ({})", file_path.to_string_lossy(), err.name());
            exit_code = err.exit_code() as i32;

            if handle_error(err) {
                return exit_code;
            }
        }
    }
    
    exit_code
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
