//! Handlers for the `databoxer key` command and its subcommands

use std::fs::File;
use std::io::Read;
use clap::ArgMatches;
use crate::{exits_on, log, options, output};

/// Handles the `databoxer key new` subcommand
pub fn handle_key_new(args: &ArgMatches) {
    let mut options = options::KeyNewOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::new_key(options) {
        Ok(_) => log!(SUCCESS, "Successfully generated new encryption key for the current profile"),
        Err(err) => {
            log!(ERROR, "Unable to generate a new encryption key");
            exits_on!(err; all);
        }
    }
}

/// Handles the `databoxer key get` subcommand
pub fn handle_key_get(args: &ArgMatches) {
    let mut options = options::KeyGetOptions::default();
    options.password = args.get_one::<String>("PASSWORD");
    options.as_byte_array = args.get_flag("AS_BYTE_ARRAY");
    
    match crate::get_key(options) {
        Ok(key) => {
            // TODO: add current profile name
            log!(SUCCESS, "Encryption key for the current profile:");
            output!("{}", key);
        }
        Err(err) => {
            log!(ERROR, "Unable to get an encryption key for the current profile");
            exits_on!(err; all);
        }
    }
}

/// Handles the `databoxer key set` subcommand
pub fn handle_key_set<'a>(args: &ArgMatches) {
    let new_key = {
        if let Some(key_path) = args.get_one::<String>("FILE") {
            get_key_from_file(key_path).unwrap_or_else(|err| {
                log!(ERROR, "Unable to read the key file: {}", err);
                std::process::exit(1)
            })
        } else {
            args.get_one::<String>("KEY").expect("Key is required").to_string()
        }
    };

    let mut options = options::KeySetOptions::default();
    options.password = args.get_one::<String>("PASSWORD");

    match crate::set_key(&new_key, options) {
        Ok(_) => log!(SUCCESS, "Successfully set a new encryption key for the current profile"),
        Err(err) => {
            log!(ERROR, "Unable to set an encryption key for the current profile");
            exits_on!(err; all);
        }
    }
}

fn get_key_from_file<'a>(key_path: &String) -> std::io::Result<String> {
    let mut file = File::open(key_path)?;
    let mut buffer = vec![0u8; 64];
    file.read_exact(&mut buffer)?;

    String::from_utf8(buffer)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}