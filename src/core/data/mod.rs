//! Contains everything related to outside data manipulations, filesystem and operating system
//! interactions

use crate::{log, Result};
use profile::DataboxerProfiles;
use config::DataboxerConfig;
use crate::core::os::data;

pub mod profile;
pub mod keys;
pub mod config;
pub mod io;
mod auth;

/// Fetches the Databoxer profiles by importing it from the file on the disk. Will return an error in
/// case of the operation failing
pub fn get_profiles() -> Result<DataboxerProfiles> {
    log!(DEBUG, "Getting Databoxer profiles");
    let data_directory = data::get_data_dir()?;
    DataboxerProfiles::import(data_directory)
}

/// Fetches the Databoxer config by importing it from the file on the disk. Will return an error in
/// case of the operation failing
#[allow(dead_code)]
pub fn get_config() -> Result<DataboxerConfig> {
    log!(DEBUG, "Getting Databoxer profiles");
    let config_directory = data::get_config_dir()?;
    DataboxerConfig::import(config_directory)
}
