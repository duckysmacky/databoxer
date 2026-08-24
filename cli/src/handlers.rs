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

use crate::path;

pub use {
    info::handle_info,
    key::*,
    profile::*,
    r#box::handle_box,
    unbox::handle_unbox,
};

/// Expands the supplied `PATH` arguments into the flat list of files to work on, descending into
/// directories and optionally their subdirectories
fn resolve_inputs(input_paths: &[PathBuf], recursive: bool) -> Vec<PathBuf> {
    path::parse_paths(input_paths.to_vec(), recursive)
}

/// Collects the supplied `OUTPUT` arguments into a queue, one output path per processed file
fn get_output_paths(paths: &[PathBuf]) -> Option<VecDeque<PathBuf>> {
    (!paths.is_empty()).then(|| VecDeque::from(paths.to_vec()))
}

/// Picks how a file is referred to in the program's output, honouring the `--show-full-path` flag
fn display_name(show_full_path: bool, path: &Path) -> OsString {
    match show_full_path {
        true => path.as_os_str().to_os_string(),
        false => path.file_name().unwrap_or(OsStr::new("<unknown file name>")).to_os_string()
    }
}

/// Returns the password supplied through the `--password` argument, prompting the user for one if
/// it was omitted. Resolved once per invocation, before any work is started
pub fn resolve_password(password: Option<&str>) -> io::Result<String> {
    match password {
        Some(password) => Ok(password.to_string()),
        None => databoxer_core::io::input::prompt_hidden("Enter the password for the current profile")
    }
}
