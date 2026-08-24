//! Handlers for the `databoxer key` command and its subcommands

use std::{fs::File, io::Read, path::Path};

use databoxer_core::{
    data::{keys, profiles::ProfileError},
    encryption::cipher, hex, log,
};

use crate::{
    command::{KeyGetArgs, KeyNewArgs, KeySetArgs},
    error::OrFail,
    output,
};

/// Handles the `databoxer key new` subcommand
pub fn handle_key_new(args: &KeyNewArgs) {
    new_key(args).or_fail_with("Unable to generate a new encryption key");
    output!(SUCCESS, "Successfully generated new encryption key for the current profile");
}

fn new_key(args: &KeyNewArgs) -> Result<(), ProfileError> {
    log!(INFO, "Generating a new encryption key for current profile");

    let key = cipher::generate_key();
    let password = super::resolve_password(args.password.as_deref())
        .or_fail_with("Unable to read the password");

    keys::set_key(&password, key)
}

/// Handles the `databoxer key get` subcommand
pub fn handle_key_get(args: &KeyGetArgs) {
    log!(INFO, "Retrieving the encryption key from the current profile");

    let password = super::resolve_password(args.password.as_deref())
        .or_fail_with("Unable to read the password");
    let key = keys::get_key(&password)
        .or_fail_with("Unable to get an encryption key for the current profile");

    let key = match args.as_byte_array {
        true => format!("{:?}", key),
        false => hex::bytes_to_string(&key)
    };

    // TODO: add current profile name
    output!(SUCCESS, "Encryption key for the current profile:");
    output!(DATA, "{}", key);
}

/// Handles the `databoxer key set` subcommand
pub fn handle_key_set(args: &KeySetArgs) {
    // read before anything else, so an unreadable key file costs neither work nor a prompt
    let new_key = read_new_key(args).or_fail_with("Unable to read the key file");

    // parsed before authenticating, so an invalid key never costs a password prompt
    let new_key = cipher::parse_key(&new_key).or_fail_with("Unable to read the supplied key");

    log!(INFO, "Setting the encryption key from the current profile");
    let password = super::resolve_password(args.password.as_deref())
        .or_fail_with("Unable to read the password");

    keys::set_key(&password, new_key)
        .or_fail_with("Unable to set an encryption key for the current profile");

    output!(SUCCESS, "Successfully set a new encryption key for the current profile");
}

/// Reads the new key, either from the file it was pointed at or straight off the command line
fn read_new_key(args: &KeySetArgs) -> std::io::Result<String> {
    match args.file.as_deref() {
        Some(key_path) => get_key_from_file(key_path),
        None => Ok(args.key.as_ref().expect("Key is required").to_string())
    }
}

fn get_key_from_file(key_path: &Path) -> std::io::Result<String> {
    let mut file = File::open(key_path)?;
    let mut buffer = vec![0u8; 64];
    file.read_exact(&mut buffer)?;

    String::from_utf8(buffer)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}
