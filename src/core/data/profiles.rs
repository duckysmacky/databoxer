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

use super::auth;
use crate::utils::io::{read_file, write_file};
use crate::core::encryption::cipher;
use crate::{log, new_err, Key, Nonce, Result};
use serde::{Deserialize, Serialize};
use std::io::{self};
use std::path::PathBuf;

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
    pub fn import(data_directory: PathBuf) -> Result<Self> {
        log!(DEBUG, "Importing Databoxer profiles");
        let profiles_file = data_directory.join(PROFILES_FILE_NAME);

        let profiles = match read_file(&profiles_file) {
            Ok(file_data) => {
                let mut profiles: ProfileData = serde_json::from_str(&file_data)?;
                profiles.file_path = profiles_file;
                profiles
            },
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    log!(INFO, "'profiles.json' file doesn't exist. Generating new profiles data");
                    Self::new(profiles_file)
                } else {
                    return Err(err.into());
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
    pub fn get_current_profile(&mut self) -> Result<&mut Profile> {
        log!(DEBUG, "Getting current profile");
        let current_profile = self.current_profile.clone();

        let profile = match current_profile {
            None => return Err(new_err!(ProfileError: NotSelected)),
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

    /// Sets the current profile to profile which name was supplied. Returns an error if given
    /// profile doesn't exist
    pub fn set_current(&mut self, password: &str, profile_name: &str) -> Result<()> {
        log!(DEBUG, "Setting current profile to '{}'", profile_name);

        let profile = self.find_profile(profile_name)?;
        profile.verify_password(password)?;
        self.current_profile = Some(profile_name.to_string());
        self.save()?;

        log!(DEBUG, "Set current profile to '{}'", profile_name);
        Ok(())
    }

    /// Deletes a profile with provided name
    pub fn delete_profile(&mut self, profile_password: &str, profile_name: &str) -> Result<()> {
        log!(DEBUG, "Trying to delete a profile with name '{}'", profile_name);

        for (i, profile) in self.profiles.iter().enumerate() {
            if profile.name == profile_name {
                profile.verify_password(profile_password)?;
                self.profiles.remove(i);
                self.current_profile = {
                    if self.profiles.is_empty() {
                        None
                    } else {
                        Some(self.profiles.get(0).unwrap().name.clone())
                    }
                };
                self.save()?;
                log!(DEBUG, "Deleted profile '{}'", profile_name);
                return Ok(())
            }
        }

        Err(new_err!(ProfileError: NotFound, profile_name))
    }

    /// Saves provided profile data to profiles file. Updates existing profile or creates a new one,
    /// if it doesn't already exist
    #[allow(dead_code)]
    pub fn save_profile(&mut self, profile: Profile) -> Result<()> {
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
    pub fn new_profile(&mut self, profile: Profile) -> Result<()> {
        log!(DEBUG, "Adding a new profile: {:?}", &profile);

        let profile_name = profile.name.clone();
        if self.find_profile(&profile_name).is_ok() {
            return Err(new_err!(ProfileError: AlreadyExists, profile_name));
        }
        self.profiles.push(profile);

        self.save()?;
        Ok(())
    }

    /// Returns profile for profile which name was supplied
    pub fn find_profile(&mut self, profile_name: &str) -> Result<&mut Profile> {
        log!(DEBUG, "Searching for profile with name '{}'", profile_name);

        for profile in &mut self.profiles {
            if profile.name == profile_name {
                return Ok(profile)
            }
        }

        Err(new_err!(ProfileError: NotFound, profile_name))
    }

    /// Writes to the profile data file. Overwrites old data
    pub fn save(&self) -> Result<()> {
        log!(DEBUG, "Saving profiles data to 'profiles.json'");
        let json_data = serde_json::to_string_pretty(&self)?;

        write_file(&self.file_path, &json_data, true)?;
        Ok(())
    }
}

/// Struct containing main information about a profile
#[derive(Serialize, Deserialize, Debug)]
pub struct Profile {
    /// Name of the profile
    pub name: String,
    /// Profile's password stored in a hashed form
    password_hash: String,
    /// Per-profile nonce used to perform encryption operations on profile's key
    nonce: Nonce,
    /// Profile's encryption key stored in an encrypted format
    key: Vec<u8>,
}

impl Profile {
    pub fn new(
        name: &str,
        password: &str
    ) -> Result<Self> {
        let (password_hash, password_key) = auth::hash_password(password)?;
        let key = cipher::generate_key();
        let nonce = cipher::generate_nonce();
        let encrypted_key = cipher::encrypt(&password_key, &nonce, &key)?;

        Ok(Profile {
            name: name.to_string(),
            key: encrypted_key,
            nonce,
            password_hash,
        })
    }

    /// Checks whether the provided password is valid for the profile by verifying it with the hash
    pub fn verify_password(&self, password: &str) -> Result<()> {
        match auth::verify_password(&self.password_hash, password) {
            Ok(_) => Ok(()),
            Err(err) => Err(err)
        }
    }

    /// Sets a new key for the profile. Encrypts provided Key based on password and saves it to the
    /// profile in the encrypted form
    pub fn set_key(&mut self, password: &str, key: Key) -> Result<()> {
        let password_key = auth::get_password_key(&self.password_hash, password)?;
        let encrypted_key = cipher::encrypt(&password_key, &self.nonce, &key)?;

        self.key = encrypted_key;
        Ok(())
    }

    /// Fetches encryption key for the current profile. Decrypts contained key based on the password
    /// after verifying it and returns it
    pub fn get_key(&self, password: &str) -> Result<Key> {
        let encrypted_key = self.key.clone();
        let password_key = auth::get_password_key(&self.password_hash, password)?;
        let key = cipher::decrypt(&password_key, &self.nonce, &encrypted_key)?.try_into()
            .map_err(|_| new_err!(InvalidData: InvalidLength, "encryption key"))?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::os::data;
    use super::*;

    #[test]
    #[ignore]
    /// Creates the `profiles.json` file in the program data directory and fills it with default
    /// information
    fn write_default_profiles() {
        let data_directory = data::get_data_dir().expect("Cannot get data directory");
        let config = ProfileData::import(data_directory);

        assert!(config.is_ok())
    }
}