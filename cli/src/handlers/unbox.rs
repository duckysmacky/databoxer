//! Handler for the `databoxer unbox` command

use clap::ArgMatches;
use std::path::PathBuf;
use std::collections::VecDeque;
use std::ffi::OsStr;
use crate::error::{self, Verdict, Policy};
use crate::handlers;
use crate::path;
use databoxer_core::{options, log};
use crate::output;

/// Handles the `databoxer unbox` subcommand. Returns a tuple containing:
/// - The total number of files processed
/// - The number of successfully decrypted files
/// - The exit code indicating the status of the operation (0 for success, non-zero for errors)
pub fn handle_unbox(args: &ArgMatches) -> (u32, u32, i32) {
    let file_paths: Vec<PathBuf> = {
        let input_paths = handlers::get_path_vec(args, "PATH").expect("File path is required");
        let recursive = args.get_flag("RECURSIVE");

        path::parse_paths(input_paths, recursive)
    };

    let mut options = options::DecryptionOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

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

    // decrypt each file and handle errors accordingly
    for path in file_paths {
        let file_name = match args.get_flag("SHOW_FULL_PATH") {
            true => path.as_os_str().to_os_string(),
            false => path.file_name().unwrap_or(OsStr::new("<unknown file name>")).to_os_string()
        };

        output!(STATUS, "Decrypting {:?}...", file_name);
        match databoxer_core::decrypt(path.as_path(), &mut options) {
            Ok(_) => {
                output!(SUCCESS, "Successfully decrypted {:?}", file_name);
                successful_files += 1;
            },
            Err(err) => {
                log!(ERROR, "Unable to decrypt '{}' ({})", file_name.to_string_lossy(), err.name());
                exit_code = err.exit_code() as i32;

                if error::report(&err, Policy::Batch) == Verdict::Abort {
                    return (total_files, successful_files, exit_code);
                }
            }
        }
    }

    (total_files, successful_files, exit_code)
}
