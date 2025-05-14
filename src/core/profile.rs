//! Contains core logic for profile manipulation subcommands

use crate::core::{data, prompt};
use crate::core::data::profile::Profile;
use crate::{log, new_err};

pub fn create(
    profile_name: &str,
    password: &Option<&String>
) -> crate::Result<()> {
    log!(INFO, "Creating a new profile with name '{}'", profile_name);
    
    let mut profiles = data::get_profiles()?;
    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    
    profiles.new_profile(Profile::new(profile_name, &password)?)?;
    Ok(())
}

pub fn delete(
    profile_name: &str,
    password: &Option<&String>
) -> crate::Result<()> {
    log!(INFO, "Deleting profile '{}'", profile_name);
    
    let mut profiles = data::get_profiles()?;
    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };

    profiles.delete_profile(&password, profile_name)?;
    Ok(())
}

pub fn select(
    profile_name: &str,
    password: &Option<&String>
) -> crate::Result<()> {
    log!(INFO, "Switching profile to '{}'", profile_name);
    let mut profiles = data::get_profiles()?;

    if let Ok(profile) = profiles.get_current_profile() {
        if profile_name == profile.name {
            return Err(new_err!(ProfileError: AlreadySelected, profile_name))
        }
    }

    let password = match password {
        None => prompt::prompt_password()?,
        Some(p) => p.to_string()
    };
    profiles.set_current(&password, profile_name)?;
    Ok(())
}

pub fn get_current() -> crate::Result<String> {
    log!(INFO, "Getting current profile");
    
    let mut profiles = data::get_profiles()?;
    let profile = profiles.get_current_profile()?;
    
    Ok(profile.name.to_string())
}

pub fn get_all() -> crate::Result<Vec<String>> {
    log!(INFO, "Listing all available profiles");

    let profiles = data::get_profiles()?;
    let profile_list = profiles.get_profiles().into_iter()
        .map(|p| p.name.to_string())
        .collect::<Vec<String>>();
    
    Ok(profile_list)
}