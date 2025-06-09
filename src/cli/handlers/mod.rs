//! Module containing handlers which are responsible for logic of the databoxer's subcommand
//! actions. Each submodule in this module corresponds to the subcommand under the main databoxer
//! command

mod profile;
mod key;
mod r#box;
mod unbox;
mod info;

use clap::ArgMatches;
use std::path::PathBuf;

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