//! Handler for the `databoxer info` command

use clap::ArgMatches;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use chrono::{DateTime, Local};
use crate::error::{self, Policy};
use crate::path;
use databoxer_core::data::boxfile::{Boxfile, FileMetadata};
use databoxer_core::{log, Result};
use crate::output;

/// Handles the `databoxer info` subcommand. Returns an exit code indicating the status of the 
/// operation (0 for success, non-zero for errors).
pub fn handle_info(args: &ArgMatches) -> i32 {
    let file_path = {
        let path = args.get_one::<String>("PATH").expect("File path is required");
        let paths = path::parse_paths(vec![PathBuf::from(path)], false);

        match paths.into_iter().next() {
            Some(path) => path,
            // `parse_paths` has already reported why nothing was found
            None => return error::CLI_FAILURE
        }
    };

    output!(STATUS, "Retrieving information about '{}'...", file_path.display());

    match get_info(&file_path, args.get_flag("SHOW_UNKNOWN")) {
        Ok(info_lines) => {
            output!(SUCCESS, "Displaying information about '{}':", file_path.display());

            for line in info_lines {
                output!(DATA, "{}", line);
            }

            0
        }
        Err(err) => {
            log!(ERROR, "Unable to get information about '{}' ({})", file_path.to_string_lossy(), err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

/// Parses the boxfile at the given path and renders what its header remembers about the original
/// file as display lines. Metadata which was never recorded is skipped unless asked for
fn get_info(input_path: &Path, show_unknown: bool) -> Result<Vec<String>> {
    log!(INFO, "Getting file information...");

    let boxfile = Boxfile::parse(input_path)?;
    Ok(format_metadata(boxfile.metadata(), show_unknown))
}

/// Renders file metadata as human-readable lines
fn format_metadata(metadata: FileMetadata, show_unknown: bool) -> Vec<String> {
    let mut file_info = Vec::new();

    if metadata.metadata_encrypted {
        file_info.push("Original file data seems to be encrypted. Unavailable to retrieve file information!".to_string());
    }

    match metadata.name {
        Some(name) => file_info.push(format!("Name: {:?}", name)),
        None => file_info.push("Name: Unknown".to_string())
    }

    match metadata.extension {
        Some(extension) => file_info.push(format!("Extension: {:?}", extension)),
        None => file_info.push("Extension: None".to_string())
    }

    match metadata.source_os {
        Some(source_os) => file_info.push(format!("OS: {:?}", source_os)),
        None => file_info.push("OS: Unknown".to_string())
    }

    // times are only worth a line of their own when they were actually recorded
    let times = [
        ("Create time", metadata.create_time),
        ("Modify time", metadata.modify_time),
        ("Access time", metadata.access_time),
    ];

    for (label, time) in times {
        match time {
            Some(time) => file_info.push(format!("{}: {}", label, format_time(time))),
            None if show_unknown => file_info.push(format!("{}: Unknown", label)),
            None => {}
        }
    }

    file_info
}

/// Formats a timestamp in the local timezone
fn format_time(system_time: SystemTime) -> String {
    let time: DateTime<Local> = system_time.into();
    format!("{}", time.format("%d.%m.%Y %T"))
}
