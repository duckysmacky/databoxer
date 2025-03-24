//! Contains handlers for the key subcommand

use clap::ArgMatches;
use crate::{exits_on, log_error, log_success, options, output};

pub fn handle_key_new(args: &ArgMatches) {
    let mut options = options::KeyNewOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::new_key(options) {
        Ok(_) => log_success!("Successfully generated new encryption key for the current profile"),
        Err(err) => {
            log_error!("Unable to generate a new encryption key");
            exits_on!(err; all);
        }
    }
}

pub fn handle_key_get(args: &ArgMatches) {
    let mut options = options::KeyGetOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    options.as_byte_array = args.get_flag("AS_BYTE_ARRAY");
    
    match crate::get_key(options) {
        Ok(key) => {
            // TODO: add current profile name
            log_success!("Encryption key for the current profile:");
            output!("{}", key);
        }
        Err(err) => {
            log_error!("Unable to get an encryption key for the current profile");
            exits_on!(err; all);
        }
    }
}

pub fn handle_key_set(args: &ArgMatches) {
    let new_key = args.get_one::<String>("KEY").expect("Key is required");
    
    let mut options = options::KeySetOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::set_key(new_key, options) {
        Ok(_) => log_success!("Successfully set a new encryption key for the current profile"),
        Err(err) => {
            log_error!("Unable to set an encryption key for the current profile");
            exits_on!(err; all);
        }
    }
}