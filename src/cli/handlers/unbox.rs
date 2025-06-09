//! Handler for the `databoxer unbox` command

use clap::ArgMatches;
use std::path::PathBuf;
use std::collections::VecDeque;
use std::ffi::OsStr;
use crate::cli::handlers;
use crate::core::utils::path;
use crate::{exits_on, log, options};

/// Handles the `databoxer unbox` subcommand
pub fn handle_unbox(args: &ArgMatches) -> (u32, u32) {
    let mut total_files: u32 = 0;
    let mut error_files: u32 = 0;

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

    // decrypt each file and handle errors accordingly
    for path in file_paths {
        total_files += 1;
        let file_name = match args.get_flag("SHOW_FULL_PATH") {
            true => path.as_os_str().to_os_string(),
            false => path.file_name().unwrap_or(OsStr::new("<unknown file name>")).to_os_string()
        };

        log!(INFO, "Decrypting {:?}", file_name);
        match crate::decrypt(path.as_path(), &mut options) {
            Ok(_) => log!(SUCCESS, "Successfully decrypted {:?}", path.file_name().unwrap().to_os_string()),
            Err(err) => {
                log!(ERROR, "Unable to decrypt '{}'", file_name.to_string_lossy());
                exits_on!(err; IOError false; InvalidInput false);
                error_files += 1;
            }
        }
    }

    (total_files, error_files)
}