//! Module containing handlers which are responsible for logic of the databoxer's subcommand
//! actions. Each submodule in this module corresponds to the subcommand under the main databoxer
//! command

mod profile;
mod key;
mod r#box;
mod unbox;
mod info;

use clap::ArgMatches;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::path;
use databoxer_core::data::{self, profiles::ProfileData};
use databoxer_core::{Key, Result};

pub use r#box::handle_box;
pub use unbox::handle_unbox;
pub use info::handle_info;
pub use key::*;
pub use profile::*;

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
pub fn resolve_password(args: &ArgMatches) -> Result<String> {
    match args.get_one::<String>("PASSWORD") {
        Some(password) => Ok(password.to_string()),
        None => databoxer_core::io::input::prompt_hidden("Enter the password for the current profile")
    }
}

/// Loads the profile data and unlocks the current profile's encryption key.
///
/// Done once per invocation rather than once per file: deriving the key from the password is
/// deliberately expensive, and the profile state is checked before the user is asked for anything
fn unlock(args: &ArgMatches) -> Result<(ProfileData, Key)> {
    let mut profiles = data::get_profiles()?;

    // fails here rather than after a pointless password prompt
    profiles.get_current_profile()?;

    let password = resolve_password(args)?;
    let key = profiles.get_current_profile()?.get_key(&password)?;

    Ok((profiles, key))
}
