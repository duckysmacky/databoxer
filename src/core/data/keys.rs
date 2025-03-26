//! Contains wrapper functions above profiles to get and set current profile's key

use crate::log;
use crate::{Key, Result};
use crate::core::data;

/// Gets the key for the current profile
pub fn get_key(password: &str) -> Result<Key> {
    log!(DEBUG, "Getting encryption key from current profile");
    let mut profiles = data::get_profiles()?;
    let profile = profiles.get_current_profile()?;
    let key = profile.get_key(password)?;
    Ok(key)
}

/// Sets the key for the current profile
pub fn set_key(password: &str, new_key: Key) -> Result<()> {
    log!(DEBUG, "Setting a new encryption key for current profile");
    let mut profiles = data::get_profiles()?;
    let profile = profiles.get_current_profile()?;
    profile.set_key(password, new_key)?;
    profiles.save()
}