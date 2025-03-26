//! Contains core logic for key manipulation subcommands

use crate::{log, new_err, Key};
use crate::core::{prompt, utils};
use crate::core::data::keys;
use crate::core::encryption::cipher;
pub fn new(
    password: &Option<&String>
) -> crate::Result<()> {
    log!(INFO, "Generating a new encryption key for current profile");
    
    let key = cipher::generate_key();
    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    
    keys::set_key(&password, key)?;
    Ok(())
}

pub fn get(
    password: &Option<&String>, 
    as_byte_array: bool
) -> crate::Result<String> {
    log!(INFO, "Retrieving the encryption key from the current profile");

    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    let key = keys::get_key(&password)?;
    
    if as_byte_array {
        return Ok(format!("{:?}", key))
    }
    Ok(utils::hex::bytes_to_string(&key))
}

pub fn set(
    new_key: &str, 
    password: &Option<&String>
) -> crate::Result<()> {
    log!(INFO, "Setting the encryption key from the current profile");
    
    let new_key = utils::hex::string_to_bytes(new_key)?;
    if new_key.len() != 32 {
        return Err(new_err!(InvalidData: InvalidHex, "Provided hex is not a 32-byte key"))
    }
    let new_key = Key::try_from(&new_key[..32]).unwrap();
    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    
    keys::set_key(&password, new_key)?;
    Ok(())
}