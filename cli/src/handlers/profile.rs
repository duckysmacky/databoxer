//! Handlers for the `databoxer profile` command and its subcommands

use clap::ArgMatches;
use databoxer_core::error;
use databoxer_core::{options, log};
use databoxer_core::output;

/// Handles the `databoxer profile create` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_create(args: &ArgMatches) -> i32 {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");
    
    let mut options = options::ProfileCreateOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    let mut exit_code = 0;
    
    match databoxer_core::create_profile(name, options) {
        Ok(_) => log!(SUCCESS, "Successfully created new profile '{}'", name),
        Err(err) => {
            log!(ERROR, "Unable to create a new profile named '{}' ({})", name, err.name());
            exit_code = err.exit_code() as i32;

            if handle_error(err) {
                return exit_code;
            }
        }
    }
    
    exit_code
}

/// Handles the `databoxer profile delete` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_delete(args: &ArgMatches) -> i32 {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    let mut options = options::ProfileDeleteOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    let mut exit_code = 0;
    
    match databoxer_core::delete_profile(name, options) {
        Ok(_) => log!(SUCCESS, "Successfully deleted profile '{}'", name),
        Err(err) => {
            log!(ERROR, "Unable to delete profile '{}' ({})", name, err.name());
            exit_code = err.exit_code() as i32;

            if handle_error(err) {
                return exit_code;
            }
        }
    }
    
    exit_code
}

/// Handles the `databoxer profile set` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_set(args: &ArgMatches) -> i32 {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    let mut options = options::ProfileSelectOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    
    let mut exit_code = 0;
    
    match databoxer_core::select_profile(name, options) {
        Ok(_) => log!(SUCCESS, "Successfully set current profile to '{}'", name),
        Err(err) => {
            log!(ERROR, "Unable to switch to profile '{}'", name);
            exit_code = err.exit_code() as i32;

            if handle_error(err) {
                return exit_code;
            }
        }
    }
    
    exit_code
}

/// Handles the `databoxer profile get` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_get(_args: &ArgMatches) -> i32 {
    match databoxer_core::get_profile() {
        Ok(name) => {
            log!(SUCCESS, "Currently selected profile:");
            output!("{}", name);
            
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to get currently selected profile ({})", err.name());
            let exit_code = err.exit_code() as i32;
            
            handle_error(err);
            exit_code
        }
    }
}

/// Handles the `databoxer profile list` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_list(_args: &ArgMatches) -> i32 {
    match databoxer_core::get_profiles() {
        Ok(profiles) => {
            let count = profiles.len();

            if count == 0 {
                log!(SUCCESS, "No profiles found");
                log!(WARN, "New profile can be created with 'databoxer profile new'");
            } else {
                if count > 1 {
                    log!(SUCCESS, "There are {} profiles found:", count);
                }
                else {
                    log!(SUCCESS, "There is {} profile found:", count);
                }

                for name in profiles {
                    output!(list "{}", name);
                }
            }
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to get a list of all profiles ({})", err.name());
            let exit_code = err.exit_code() as i32;
            handle_error(err);
            exit_code
        }
    }
    
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