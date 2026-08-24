//! Module containing everything related to Databoxer profile management.
//! 
//! Provides a base struct `DataboxerProfiles` used for holding information about user's profiles
//! which is represented as a `profiles.toml` file on the disk, which is located in the program's 
//! default data directory. 
//! 
//! Also contains a `Profile` struct which is used for storing information
//! about particular user profile. Each profile consists of unique name, password and key with its
//! main goal is to hold the stated encryption key. There can be many profiles created at the same
//! time, but each has to have a unique name. `Key` is generated with the creation of the profile
//! which it belongs to. Password is also hashed automatically on creation and stored in that form
//! on the disk

use std::{io, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    io::fs::{read_file, write_file},
    log,
};
use super::{Profile, ProfileError};

/// Name of the file which stores all the profile data
const PROFILES_FILE_NAME: &str = "profiles.json";

/// Struct holding all the needed profile information for the program. Saved on the disk as a JSON
/// file
#[derive(Serialize, Deserialize, Debug)]
pub struct ProfileData {
    current_profile: Option<String>,
    profiles: Vec<Profile>,
    #[serde(skip)]
    file_path: PathBuf
}

/// Object-driven approach
impl ProfileData {
    /// Imports self from the stored "profiles.json" file in the program's data directory. In case
    /// of the file missing, generates a new object with default empty values
    pub fn import(data_directory: PathBuf) -> Result<Self, ProfileError> {
        log!(DEBUG, "Importing Databoxer profiles");
        let profiles_file = data_directory.join(PROFILES_FILE_NAME);

        let profiles = match read_file(&profiles_file) {
            Ok(file_data) => {
                let mut profiles: ProfileData = serde_json::from_str(&file_data)
                    .map_err(|source| ProfileError::Deserialize {
                        path: profiles_file.clone(), source
                    })?;
                profiles.file_path = profiles_file;
                profiles
            },
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    log!(INFO, "'profiles.json' file doesn't exist. Generating new profiles data");
                    Self::new(profiles_file)
                } else {
                    return Err(ProfileError::io(profiles_file)(err));
                }
            }
        };

        Ok(profiles)
    }

    /// Bare-minimum constructor to use in case of file not being available to import from
    fn new(
        file_path: PathBuf
    ) -> Self {
        ProfileData {
            current_profile: None,
            profiles: vec![],
            file_path
        }
    }

    /// Returns currently selected profile data
    pub fn get_current_profile(&mut self) -> Result<&mut Profile, ProfileError> {
        log!(DEBUG, "Getting current profile");
        let current_profile = self.current_profile.clone();

        let profile = match current_profile {
            None => return Err(ProfileError::NotSelected),
            Some(profile_name) => {
                self.find_profile(&profile_name)?
            }
        };

        Ok(profile)
    }
    
    /// Returns a list of currently available profiles
    pub fn get_profiles(&self) -> &Vec<Profile> {
        log!(DEBUG, "Getting all available profiles");
        &self.profiles
    }

    /// Errors if no profile with the supplied name exists.
    ///
    /// Needs no authentication, so a frontend can call it before asking the user for a password
    pub fn ensure_exists(&self, profile_name: &str) -> Result<(), ProfileError> {
        match self.profiles.iter().any(|profile| profile.name == profile_name) {
            true => Ok(()),
            false => Err(ProfileError::NotFound(profile_name.to_string()))
        }
    }

    /// Errors if a profile with the supplied name already exists.
    ///
    /// Needs no authentication, so a frontend can call it before asking the user for a password
    pub fn ensure_absent(&self, profile_name: &str) -> Result<(), ProfileError> {
        match self.profiles.iter().any(|profile| profile.name == profile_name) {
            true => Err(ProfileError::AlreadyExists(profile_name.to_string())),
            false => Ok(())
        }
    }

    /// Errors if the supplied profile cannot become the current one, either because it doesn't
    /// exist or because it is selected already.
    ///
    /// Needs no authentication, so a frontend can call it before asking the user for a password
    pub fn ensure_selectable(&self, profile_name: &str) -> Result<(), ProfileError> {
        // a missing profile is reported as such, even when its name matches the current one
        self.ensure_exists(profile_name)?;

        if self.current_profile.as_deref() == Some(profile_name) {
            return Err(ProfileError::AlreadySelected(profile_name.to_string()));
        }

        Ok(())
    }

    /// Sets the current profile to profile which name was supplied. Returns an error if given
    /// profile doesn't exist, or if it is already the current one
    pub fn set_current(&mut self, password: &str, profile_name: &str) -> Result<(), ProfileError> {
        log!(DEBUG, "Setting current profile to '{}'", profile_name);
        self.ensure_selectable(profile_name)?;

        let profile = self.find_profile(profile_name)?;
        profile.verify_password(password)?;
        self.current_profile = Some(profile_name.to_string());
        self.save()?;

        log!(DEBUG, "Set current profile to '{}'", profile_name);
        Ok(())
    }

    /// Deletes a profile with provided name
    pub fn delete_profile(
        &mut self,
        profile_password: &str,
        profile_name: &str
    ) -> Result<(), ProfileError> {
        log!(DEBUG, "Trying to delete a profile with name '{}'", profile_name);

        for (i, profile) in self.profiles.iter().enumerate() {
            if profile.name == profile_name {
                profile.verify_password(profile_password)?;
                self.profiles.remove(i);
                self.current_profile = self.profiles.first().map(|profile| profile.name.clone());
                self.save()?;
                log!(DEBUG, "Deleted profile '{}'", profile_name);
                return Ok(())
            }
        }

        Err(ProfileError::NotFound(profile_name.to_string()))
    }

    /// Saves provided profile data to profiles file. Updates existing profile or creates a new one,
    /// if it doesn't already exist
    #[allow(dead_code)]
    pub fn save_profile(&mut self, profile: Profile) -> Result<(), ProfileError> {
        log!(DEBUG, "Saving profile: {:?}", &profile);

        let profile_name = profile.name.clone();

        if self.profiles.is_empty() {
            self.profiles.push(profile);
            self.current_profile = Some(profile_name);
        } else {
            for i in 0..self.profiles.len() {
                if self.profiles[i].name == profile_name {
                    self.profiles.insert(i, profile);
                    break;
                }

                if i == self.profiles.len() - 1 {
                    self.profiles.push(profile);
                    break;
                }
            }
        }

        self.save()?;
        Ok(())
    }

    /// Adds a new profile to the profiles file. Errors if the profile already exists, as this
    /// functions only accepts new profiles
    pub fn new_profile(&mut self, profile: Profile) -> Result<(), ProfileError> {
        log!(DEBUG, "Adding a new profile: {:?}", &profile);

        self.ensure_absent(&profile.name)?;
        self.profiles.push(profile);

        self.save()?;
        Ok(())
    }

    /// Returns profile for profile which name was supplied
    pub fn find_profile(&mut self, profile_name: &str) -> Result<&mut Profile, ProfileError> {
        log!(DEBUG, "Searching for profile with name '{}'", profile_name);

        for profile in &mut self.profiles {
            if profile.name == profile_name {
                return Ok(profile)
            }
        }

        Err(ProfileError::NotFound(profile_name.to_string()))
    }

    /// Writes to the profile data file. Overwrites old data
    pub fn save(&self) -> Result<(), ProfileError> {
        log!(DEBUG, "Saving profiles data to 'profiles.json'");
        let json_data = serde_json::to_string_pretty(&self)?;

        write_file(&self.file_path, &json_data, true)
            .map_err(ProfileError::io(&self.file_path))?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use crate::{encryption::cipher, os::data};

    use super::*;
    
    /// Creates the `profiles.json` file in the program data directory and fills it with default
    /// information
    #[test]
    #[ignore]
    fn write_default_profiles() {
        let data_directory = data::get_data_dir().expect("Cannot get data directory");
        let config = ProfileData::import(data_directory);

        assert!(config.is_ok())
    }
    
    /// Tests profile's password verification process
    #[test]
    fn test_password_verification() -> Result<(), ProfileError> {
        const PASSWORD: &str = "test-password123";
        
        let profile = Profile::new("test", PASSWORD)?;
        profile.verify_password(PASSWORD)
    }
    
    /// Selecting the profile which is already current is rejected, while a profile which doesn't
    /// exist is reported as missing even when it shares the current profile's name
    #[test]
    fn test_set_current_guards() -> Result<(), ProfileError> {
        const PASSWORD: &str = "test-password123";

        let mut data = ProfileData::new(PathBuf::from("profiles.json"));
        data.profiles.push(Profile::new("first", PASSWORD)?);
        data.profiles.push(Profile::new("second", PASSWORD)?);
        data.current_profile = Some("first".to_string());

        let already_selected = data.set_current(PASSWORD, "first").unwrap_err();
        assert!(matches!(already_selected, ProfileError::AlreadySelected(_)));

        let not_found = data.set_current(PASSWORD, "missing").unwrap_err();
        assert!(matches!(not_found, ProfileError::NotFound(_)));

        data.current_profile = Some("gone".to_string());
        let stale_current = data.set_current(PASSWORD, "gone").unwrap_err();
        assert!(matches!(stale_current, ProfileError::NotFound(_)));

        Ok(())
    }

    /// Tests if the originally set key will be equal to the decrypted key
    #[test]
    fn test_profile_key_encryption() -> Result<(), ProfileError> {
        const PASSWORD: &str = "test-password123";
        
        let mut profile = Profile::new("test", PASSWORD)?;
        
        let original_key = cipher::generate_key();
        profile.set_key(PASSWORD, original_key)?;
        
        let decrypted_key = profile.get_key(PASSWORD)?;
        assert_eq!(original_key, decrypted_key, "Original and decrypted keys are different");
        
        Ok(())
    }
}
