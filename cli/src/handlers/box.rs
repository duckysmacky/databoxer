//! Handler for the the `databoxer box` command

use clap::ArgMatches;
use std::fs;
use std::path::Path;
use crate::error::{self, Verdict, Policy};
use crate::handlers;
use crate::naming::{self, OutputPaths};
use databoxer_core::data::boxfile::Boxfile;
use databoxer_core::{log, Key, Result};
use crate::output;

/// Handles the `databoxer box` subcommand. Returns a tuple containing:
/// - The total number of files processed
/// - The number of successfully encrypted files
/// - The exit code indicating the status of the operation (0 for success, non-zero for errors)
pub fn handle_box(args: &ArgMatches) -> (u32, u32, i32) {
    let file_paths = handlers::resolve_inputs(args);
    let total_files = file_paths.len() as u32;

    let keep_original_name = args.get_flag("KEEP_NAME");
    let generate_padding = !args.get_flag("NO_PADDING");
    let encrypt_metadata = args.get_flag("ENCRYPT_METADATA");

    // authenticate once for the whole batch, before a single file is touched
    let (mut profiles, key) = match handlers::unlock(args) {
        Ok(unlocked) => unlocked,
        Err(err) => {
            log!(ERROR, "Unable to start encryption ({})", err.name());
            error::report(&err, Policy::Single);
            return (total_files, 0, err.exit_code() as i32);
        }
    };

    let mut output_paths = OutputPaths::new(handlers::get_output_paths(args));
    let mut successful_files: u32 = 0;
    let mut exit_code: i32 = 0;

    log!(INFO, "Starting encryption...");

    // encrypt each file and handle errors accordingly
    for input_path in file_paths {
        let file_name = handlers::display_name(args, &input_path);
        let output_path = output_paths.take_next()
            .unwrap_or_else(|| naming::boxed_path(&input_path, keep_original_name));

        output!(STATUS, "Encrypting {:?}...", file_name);

        match encrypt_file(&key, &input_path, &output_path, generate_padding, encrypt_metadata) {
            Ok(_) => {
                // the original is only removed once its replacement is safely on disk
                if let Err(err) = fs::remove_file(&input_path) {
                    log!(WARN, "Unable to remove the original '{}': {}", input_path.display(), err);
                }

                if let Ok(profile) = profiles.get_current_profile() {
                    profile.add_associated_file(&output_path);
                }

                output!(SUCCESS, "Successfully encrypted {:?}", file_name);
                successful_files += 1;
            },
            Err(err) => {
                log!(ERROR, "Unable to encrypt '{}' ({})", file_name.to_string_lossy(), err.name());

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

/// Boxes a single file, writing the result to the given destination. Non-destructive: the original
/// is left for the caller to deal with
fn encrypt_file(
    key: &Key,
    input_path: &Path,
    output_path: &Path,
    generate_padding: bool,
    encrypt_metadata: bool
) -> Result<()> {
    let mut boxfile = Boxfile::new(input_path, generate_padding, encrypt_metadata)?;
    boxfile.encrypt_data(key)?;
    boxfile.save_to(output_path)
}
