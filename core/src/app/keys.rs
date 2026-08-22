//! Contains core logic for key manipulation subcommands

use crate::{log, new_err, Key};
use crate::{prompt, data::keys, encryption::cipher};
use crate::hex;

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
    Ok(hex::bytes_to_string(&key))
}

pub fn set(
    new_key: &str, 
    password: &Option<&String>
) -> crate::Result<()> {
    log!(INFO, "Setting the encryption key from the current profile");
    
    let key_bytes = hex::string_to_bytes(new_key)?;
    if key_bytes.len() != 32 {
        return Err(new_err!(InvalidData: InvalidHex, new_key.to_string(); "Provided hex is not a 32-byte key"))
    }
    let new_key = Key::try_from(&key_bytes[..32]).unwrap();
    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    
    keys::set_key(&password, new_key)?;
    Ok(())
}