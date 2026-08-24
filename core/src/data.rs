//! Contains everything related to outside data manipulations, filesystem and operating system
//! interactions

pub mod boxfile;
pub mod config;
pub mod keys;
pub mod profiles;
mod auth;

use crate::{
    os::data,
    log
};
use self::{
    config::{ConfigError, DataboxerConfig},
    profiles::{ProfileData, ProfileError},
};

/// Fetches the Databoxer profiles by importing it from the file on the disk. Will return an error in
/// case of the operation failing
pub fn get_profiles() -> Result<ProfileData, ProfileError> {
    log!(DEBUG, "Getting Databoxer profiles");
    let data_directory = data::get_data_dir().map_err(ProfileError::DataDir)?;
    ProfileData::import(data_directory)
}

/// Fetches the Databoxer config by importing it from the file on the disk. Will return an error in
/// case of the operation failing
#[allow(dead_code)]
pub fn get_config() -> Result<DataboxerConfig, ConfigError> {
    log!(DEBUG, "Getting Databoxer profiles");
    let config_directory = data::get_config_dir().map_err(ConfigError::ConfigDir)?;
    DataboxerConfig::import(config_directory)
}
