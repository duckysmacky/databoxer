//! Handlers for the `databoxer profile` command and its subcommands

use clap::ArgMatches;

use databoxer_core::{
    data::{self, profiles::Profile},
    log, Result,
};

use crate::{error::{self, Policy}, output};

/// Handles the `databoxer profile create` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_create(args: &ArgMatches) -> i32 {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    match create_profile(args, name) {
        Ok(_) => {
            output!(SUCCESS, "Successfully created new profile '{}'", name);
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to create a new profile named '{}' ({})", name, err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

fn create_profile(args: &ArgMatches, name: &str) -> Result<()> {
    let mut profiles = data::get_profiles()?;

    // checked before authenticating, so a doomed request never costs a password prompt
    profiles.ensure_absent(name)?;

    let password = super::resolve_password(args)?;
    profiles.new_profile(Profile::new(name, &password)?)
}

/// Handles the `databoxer profile delete` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_delete(args: &ArgMatches) -> i32 {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    match delete_profile(args, name) {
        Ok(_) => {
            output!(SUCCESS, "Successfully deleted profile '{}'", name);
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to delete profile '{}' ({})", name, err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

fn delete_profile(args: &ArgMatches, name: &str) -> Result<()> {
    let mut profiles = data::get_profiles()?;
    profiles.ensure_exists(name)?;

    let password = super::resolve_password(args)?;
    profiles.delete_profile(&password, name)
}

/// Handles the `databoxer profile set` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_set(args: &ArgMatches) -> i32 {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    match select_profile(args, name) {
        Ok(_) => {
            output!(SUCCESS, "Successfully set current profile to '{}'", name);
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to switch to profile '{}' ({})", name, err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

fn select_profile(args: &ArgMatches, name: &str) -> Result<()> {
    let mut profiles = data::get_profiles()?;
    profiles.ensure_selectable(name)?;

    let password = super::resolve_password(args)?;
    profiles.set_current(&password, name)
}

/// Handles the `databoxer profile get` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_get(_args: &ArgMatches) -> i32 {
    // no authentication needed, as only the name is read
    let current = data::get_profiles()
        .and_then(|mut profiles| Ok(profiles.get_current_profile()?.name.clone()));

    match current {
        Ok(name) => {
            output!(SUCCESS, "Currently selected profile:");
            output!(DATA, "{}", name);
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to get currently selected profile ({})", err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

/// Handles the `databoxer profile list` subcommand. Returns an exit code indicating the status of
/// the operation (0 for success, non-zero for errors).
pub fn handle_profile_list(_args: &ArgMatches) -> i32 {
    // no authentication needed, as only the names are read
    let names = data::get_profiles().map(|profiles| profiles.get_profiles()
        .iter()
        .map(|profile| profile.name.clone())
        .collect::<Vec<String>>()
    );

    match names {
        Ok(names) => {
            let count = names.len();

            if count == 0 {
                output!(SUCCESS, "No profiles found");
                log!(WARN, "New profile can be created with 'databoxer profile new'");
            } else {
                if count > 1 {
                    output!(SUCCESS, "There are {} profiles found:", count);
                }
                else {
                    output!(SUCCESS, "There is {} profile found:", count);
                }

                for name in names {
                    output!(DATA, "{}", name);
                }
            }
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to get a list of all profiles ({})", err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}
