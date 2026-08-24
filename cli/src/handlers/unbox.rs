//! Handler for the `databoxer unbox` command

use clap::ArgMatches;
use std::fs;
use std::path::{Path, PathBuf};
use crate::error::{self, Verdict, Policy};
use crate::handlers;
use crate::naming::{self, OutputPaths};
use databoxer_core::data::boxfile::Boxfile;
use databoxer_core::{log, Key, Result};
use crate::output;

/// The result of restoring a single boxfile
struct Restored {
    /// Whether the recovered data matched the checksum stored alongside it
    checksum_verified: bool,
}

/// Handles the `databoxer unbox` subcommand. Returns a tuple containing:
/// - The total number of files processed
/// - The number of successfully decrypted files
/// - The exit code indicating the status of the operation (0 for success, non-zero for errors)
pub fn handle_unbox(args: &ArgMatches) -> (u32, u32, i32) {
    let file_paths = handlers::resolve_inputs(args);
    let total_files = file_paths.len() as u32;

    // authenticate once for the whole batch, before a single file is touched
    let (mut profiles, key) = match handlers::unlock(args) {
        Ok(unlocked) => unlocked,
        Err(err) => {
            log!(ERROR, "Unable to start decryption ({})", err.name());
            error::report(&err, Policy::Single);
            return (total_files, 0, err.exit_code() as i32);
        }
    };

    let mut output_paths = OutputPaths::new(handlers::get_output_paths(args));
    let mut successful_files: u32 = 0;
    let mut exit_code: i32 = 0;

    log!(INFO, "Starting decryption...");

    // decrypt each file and handle errors accordingly
    for input_path in file_paths {
        let file_name = handlers::display_name(args, &input_path);
        let supplied_output = output_paths.take_next();

        output!(STATUS, "Decrypting {:?}...", file_name);

        match decrypt_file(&key, &input_path, supplied_output) {
            Ok(restored) => {
                // data which failed verification is left boxed as well as restored, since the
                // boxfile is the only other copy of it
                if restored.checksum_verified {
                    if let Err(err) = fs::remove_file(&input_path) {
                        log!(WARN, "Unable to remove '{}': {}", input_path.display(), err);
                    }

                    if let Ok(profile) = profiles.get_current_profile() {
                        profile.remove_associated_file(&input_path);
                    }
                } else {
                    log!(WARN, "Keeping '{}', as its contents could not be verified", input_path.display());
                }

                output!(SUCCESS, "Successfully decrypted {:?}", file_name);
                successful_files += 1;
            },
            Err(err) => {
                log!(ERROR, "Unable to decrypt '{}' ({})", file_name.to_string_lossy(), err.name());

                // the first failure is the one worth reporting through the exit code
                if exit_code == 0 {
                    exit_code = err.exit_code() as i32;
                }

                if error::report(&err, Policy::Batch) == Verdict::Abort {
                    break;
                }
            }
        }
    }

    // written once for the whole batch, on the aborted path as well as the normal one
    if let Err(err) = profiles.save() {
        log!(ERROR, "Unable to save the profile data ({})", err.name());
        error::report(&err, Policy::Single);
    }

    (total_files, successful_files, exit_code)
}

/// Restores a single boxfile to the supplied destination, or to one derived from the metadata the
/// boxfile remembers. Non-destructive: the boxfile is left for the caller to deal with
fn decrypt_file(key: &Key, input_path: &Path, supplied_output: Option<PathBuf>) -> Result<Restored> {
    let mut boxfile = Boxfile::parse(input_path)?;
    boxfile.decrypt_data(key)?;

    // the original name is only readable once the header has been decrypted, so the destination
    // cannot be decided any earlier than this
    let metadata = boxfile.metadata();
    let output_path = supplied_output.unwrap_or_else(|| naming::restored_path(
        input_path,
        metadata.name.as_deref(),
        metadata.extension.as_deref()
    ));

    log!(INFO, "Validating checksum...");
    let checksum_verified = boxfile.verify_checksum()?;

    if checksum_verified {
        log!(INFO, "Checksum verification successful");
    } else {
        log!(WARN, "Checksum verification failed. Data seems to be tampered with");
    }

    boxfile.restore_to(&output_path)?;

    Ok(Restored { checksum_verified })
}
