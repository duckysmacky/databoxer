//! Handlers for the `databoxer key` command and its subcommands

use std::fs::File;
use std::io::Read;
use clap::ArgMatches;
use crate::error::{self, Policy};
use databoxer_core::data::keys;
use databoxer_core::encryption::cipher;
use databoxer_core::{hex, log, Result};
use crate::output;

/// Handles the `databoxer key new` subcommand. Returns an exit code indicating the status of the
/// operation (0 for success, non-zero for errors).
pub fn handle_key_new(args: &ArgMatches) -> i32 {
    match new_key(args) {
        Ok(_) => {
            output!(SUCCESS, "Successfully generated new encryption key for the current profile");
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to generate a new encryption key ({})", err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

fn new_key(args: &ArgMatches) -> Result<()> {
    log!(INFO, "Generating a new encryption key for current profile");

    let key = cipher::generate_key();
    let password = super::resolve_password(args)?;

    keys::set_key(&password, key)
}

/// Handles the `databoxer key get` subcommand. Returns an exit code indicating the status of the
/// operation (0 for success, non-zero for errors).
pub fn handle_key_get(args: &ArgMatches) -> i32 {
    match get_key(args) {
        Ok(key) => {
            // TODO: add current profile name
            output!(SUCCESS, "Encryption key for the current profile:");
            output!(DATA, "{}", key);
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to get an encryption key for the current profile ({})", err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

fn get_key(args: &ArgMatches) -> Result<String> {
    log!(INFO, "Retrieving the encryption key from the current profile");

    let password = super::resolve_password(args)?;
    let key = keys::get_key(&password)?;

    match args.get_flag("AS_BYTE_ARRAY") {
        true => Ok(format!("{:?}", key)),
        false => Ok(hex::bytes_to_string(&key))
    }
}

/// Handles the `databoxer key set` subcommand. Returns an exit code indicating the status of the
/// operation (0 for success, non-zero for errors).
pub fn handle_key_set(args: &ArgMatches) -> i32 {
    // read before anything else, so an unreadable key file costs neither work nor a prompt
    let new_key = match read_new_key(args) {
        Ok(new_key) => new_key,
        Err(err) => {
            log!(ERROR, "Unable to read the key file: {}", err);
            return error::CLI_FAILURE;
        }
    };

    match set_key(args, &new_key) {
        Ok(_) => {
            output!(SUCCESS, "Successfully set a new encryption key for the current profile");
            0
        },
        Err(err) => {
            log!(ERROR, "Unable to set an encryption key for the current profile ({})", err.name());
            error::report(&err, Policy::Single);
            err.exit_code() as i32
        }
    }
}

/// Reads the new key, either from the file it was pointed at or straight off the command line
fn read_new_key(args: &ArgMatches) -> std::io::Result<String> {
    match args.get_one::<String>("FILE") {
        Some(key_path) => get_key_from_file(key_path),
        None => Ok(args.get_one::<String>("KEY").expect("Key is required").to_string())
    }
}

fn set_key(args: &ArgMatches, new_key: &str) -> Result<()> {
    log!(INFO, "Setting the encryption key from the current profile");

    // parsed before authenticating, so an invalid key never costs a password prompt
    let new_key = cipher::parse_key(new_key)?;
    let password = super::resolve_password(args)?;

    keys::set_key(&password, new_key)
}

fn get_key_from_file(key_path: &String) -> std::io::Result<String> {
    let mut file = File::open(key_path)?;
    let mut buffer = vec![0u8; 64];
    file.read_exact(&mut buffer)?;

    String::from_utf8(buffer)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}
