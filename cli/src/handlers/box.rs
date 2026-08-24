//! Handler for the the `databoxer box` command

use clap::ArgMatches;
use crate::error::{self, Verdict, Policy};
use crate::handlers;
use databoxer_core::{options, log};
use crate::output;

/// Handles the `databoxer box` subcommand. Returns a tuple containing:
/// - The total number of files processed
/// - The number of successfully encrypted files
/// - The exit code indicating the status of the operation (0 for success, non-zero for errors)
pub fn handle_box(args: &ArgMatches) -> (u32, u32, i32) {
    let file_paths = handlers::resolve_inputs(args);

    let mut options = options::EncryptionOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    options.keep_original_name = args.get_flag("KEEP_NAME");
    options.generate_padding = !args.get_flag("NO_PADDING");
    options.encrypt_metadata = args.get_flag("ENCRYPT_METADATA");
    options.output_paths = handlers::get_output_paths(args);

    let total_files: u32 = file_paths.len() as u32;
    let mut successful_files: u32 = 0;
    let mut exit_code: i32 = 0;
    
    // encrypt each file and handle errors accordingly
    for path in file_paths {
        let file_name = handlers::display_name(args, &path);

        output!(STATUS, "Encrypting {:?}...", file_name);
        match databoxer_core::encrypt(path.as_path(), &mut options) {
            Ok(_) => {
                output!(SUCCESS, "Successfully encrypted {:?}", file_name);
                successful_files += 1;
            },
            Err(err) => {
                log!(ERROR, "Unable to encrypt '{}' ({})", file_name.to_string_lossy(), err.name());
                exit_code = err.exit_code() as i32;

                if error::report(&err, Policy::Batch) == Verdict::Abort {
                    return (total_files, successful_files, exit_code);
                }
            }
        }
    }

    (total_files, successful_files, exit_code)
}
