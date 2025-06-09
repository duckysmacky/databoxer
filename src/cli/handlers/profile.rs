//! Handlers for the `databoxer profile` command and its subcommands

use clap::ArgMatches;
use crate::{exits_on, log, options, output};

/// Handles the `databoxer profile create` subcommand
pub fn handle_profile_create(args: &ArgMatches) {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");
    
    let mut options = options::ProfileCreateOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::create_profile(name, options) {
        Ok(_) => log!(SUCCESS, "Successfully created new profile '{}'", name),
        Err(err) => {
            log!(ERROR, "Unable to create a new profile named '{}'", name);
            exits_on!(err; all);
        }
    }
}

/// Handles the `databoxer profile delete` subcommand
pub fn handle_profile_delete(args: &ArgMatches) {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    let mut options = options::ProfileDeleteOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::delete_profile(name, options) {
        Ok(_) => log!(SUCCESS, "Successfully deleted profile '{}'", name),
        Err(err) => {
            log!(ERROR, "Unable to delete profile '{}'", name);
            exits_on!(err; all);
        }
    }
}

/// Handles the `databoxer profile set` subcommand
pub fn handle_profile_set(args: &ArgMatches) {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    let mut options = options::ProfileSelectOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    
    match crate::select_profile(name, options) {
        Ok(_) => log!(SUCCESS, "Successfully set current profile to '{}'", name),
        Err(err) => {
            log!(ERROR, "Unable to switch to profile '{}'", name);
            exits_on!(err; all);
        }
    }
}

/// Handles the `databoxer profile get` subcommand
pub fn handle_profile_get(_args: &ArgMatches) {
    match crate::get_profile() {
        Ok(name) => {
            log!(SUCCESS, "Currently selected profile:");
            output!("{}", name);
        },
        Err(err) => {
            log!(ERROR, "Unable to get currently selected profile");
            exits_on!(err; all);
        }
    }
}

/// Handles the `databoxer profile list` subcommand
pub fn handle_profile_list(_args: &ArgMatches) {
    let profiles = crate::get_profiles();

    let profiles = profiles.unwrap_or_else(|err| {
        log!(ERROR, "Unable to get a list of all profiles");
        exits_on!(err; all);
    });
    let count = profiles.len();

    if count == 0 {
        log!(WARN, "No profiles found");
        log!(WARN, "New profile can be created with 'databoxer profile new'");
    } else {
        if count > 1 {
            log!(SUCCESS, "There are {} profiles found:", count);
        }
        else {
            log!(SUCCESS, "There is {} profile found:", count);
        }
        
        for name in profiles {
            output!(list "{}", name);
        }
    }
}