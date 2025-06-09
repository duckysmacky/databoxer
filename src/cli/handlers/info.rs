//! Handler for the `databoxer info` command

use clap::ArgMatches;
use std::path::PathBuf;
use crate::utils::path;
use crate::{exits_on, log, options};

/// Handles the `databoxer info` subcommand
pub fn handle_info(args: &ArgMatches) {
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

    let file_info = crate::get_info(&file_path, options);
    match file_info {
        Ok(info_lines) => {
            log!(SUCCESS, "Displaying information about '{}':", file_path.display());
            for line in info_lines {
                println!(" - {}", line);
            }
        }
        Err(err) => {
            log!(ERROR, "Unable to get information about '{}'", file_path.display());
            exits_on!(err; all);
        }
    }
}