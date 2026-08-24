//! Module containing handlers which are responsible for logic of the databoxer's subcommand
//! actions. Each submodule in this module corresponds to the subcommand under the main databoxer
//! command

mod r#box;
mod info;
mod key;
mod profile;
mod unbox;

use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
};

use clap::ArgMatches;

use crate::path;

pub use {
    info::handle_info,
    key::*,
    profile::*,
    r#box::handle_box,
    unbox::handle_unbox,
};

/// Converts from the passed arguments strings to vector of paths
fn get_path_vec(args: &ArgMatches, arg_id: &str) -> Option<Vec<PathBuf>> {
    if let Some(strings) = args.get_many::<String>(arg_id) {
        return Some(strings
            .map(|s| PathBuf::from(s))
            .collect::<Vec<PathBuf>>()
        )
    }
    None
}

/// Expands the supplied `PATH` arguments into the flat list of files to work on, descending into
/// directories and optionally their subdirectories
fn resolve_inputs(args: &ArgMatches) -> Vec<PathBuf> {
    let input_paths = get_path_vec(args, "PATH").expect("File path is required");
    let recursive = args.get_flag("RECURSIVE");

    path::parse_paths(input_paths, recursive)
}

/// Collects the supplied `OUTPUT` arguments into a queue, one output path per processed file
fn get_output_paths(args: &ArgMatches) -> Option<VecDeque<PathBuf>> {
    let paths = get_path_vec(args, "OUTPUT")?;
    Some(VecDeque::from(paths))
}

/// Picks how a file is referred to in the program's output, honouring the `--show-full-path` flag
fn display_name(args: &ArgMatches, path: &Path) -> OsString {
    match args.get_flag("SHOW_FULL_PATH") {
        true => path.as_os_str().to_os_string(),
        false => path.file_name().unwrap_or(OsStr::new("<unknown file name>")).to_os_string()
    }
}

/// Returns the password supplied through the `--password` argument, prompting the user for one if
/// it was omitted. Resolved once per invocation, before any work is started
pub fn resolve_password(args: &ArgMatches) -> io::Result<String> {
    match args.get_one::<String>("PASSWORD") {
        Some(password) => Ok(password.to_string()),
        None => databoxer_core::io::input::prompt_hidden("Enter the password for the current profile")
    }
}
