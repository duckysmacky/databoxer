//! Contains handlers for the profile subcommand

use clap::ArgMatches;
use crate::{exits_on, log_error, log_success, log_warn, options, output};

pub fn handle_profile_create(args: &ArgMatches) {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");
    
    let mut options = options::ProfileCreateOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::create_profile(name, options) {
        Ok(_) => log_success!("Successfully created new profile \"{}\"", name),
        Err(err) => {
            log_error!("Unable to create a new profile named \"{}\"", name);
            exits_on!(err; all);
        }
    }
}

pub fn handle_profile_delete(args: &ArgMatches) {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    let mut options = options::ProfileDeleteOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::delete_profile(name, options) {
        Ok(_) => log_success!("Successfully deleted profile \"{}\"", name),
        Err(err) => {
            log_error!("Unable to delete profile \"{}\"", name);
            exits_on!(err; all);
        }
    }
}

pub fn handle_profile_set(args: &ArgMatches) {
    let name = args.get_one::<String>("NAME").expect("Profile name is required");

    let mut options = options::ProfileSelectOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    
    match crate::select_profile(name, options) {
        Ok(_) => log_success!("Successfully set current profile to \"{}\"", name),
        Err(err) => {
            log_error!("Unable to switch to profile \"{}\"", name);
            exits_on!(err; all);
        }
    }
}

pub fn handle_profile_get(_args: &ArgMatches) {
    match crate::get_profile() {
        Ok(name) => {
            log_success!("Currently selected profile:");
            output!("{}", name);
        },
        Err(err) => {
            log_error!("Unable to get currently selected profile");
            exits_on!(err; all);
        }
    }
}

pub fn handle_profile_list(_args: &ArgMatches) {
    let profiles = crate::get_profiles();

    let profiles = profiles.unwrap_or_else(|err| {
        log_error!("Unable to get a list of all profiles");
        exits_on!(err; all);
    });
    let count = profiles.len();

    if count == 0 {
        log_warn!("No profiles found");
        log_warn!("New profile can be created with \"databoxer profile new\"");
    } else {
        if count > 1 {
            log_success!("There are {} profiles found:", count);
        }
        else {
            log_success!("There is {} profile found:", count);
        }
        
        for name in profiles {
            output!(list "{}", name);
        }
    }
}