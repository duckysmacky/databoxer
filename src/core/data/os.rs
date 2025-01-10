//! Contains functions which rely on operating system with their functionality and return values
//! depending on it

use std::path::PathBuf;
use std::{env, fs};
use crate::{Error, Result};

/// Returns the application data directory based on the OS. Used for storing profiles and other
/// information for program's functionality which is not meant to be edited by the user
pub fn get_data_dir() -> Result<PathBuf> {
    let home_path = env::var("HOME")
        .map_err(|err| Error::OSError(err.to_string()))?;
    let mut data_dir = PathBuf::from(home_path);

    if cfg!(target_os = "windows") {
        data_dir.push("Lockbox/Data/");
    } else if cfg!(target_os = "macos") {
        data_dir.push("Library/Application Support/Lockbox/");
    } else { // Assuming Linux or other Unix-like OS
        data_dir.push(".local/share/lockbox/");
    }

    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }
    Ok(data_dir)
}

/// Returns the application config directory based on the OS. Used for storing configuration files
/// which can be edited by user to change program's functionality
pub fn get_config_dir() -> Result<PathBuf> {
    let home_path = env::var("HOME")
        .map_err(|err| Error::OSError(err.to_string()))?;
    let mut config_dir = PathBuf::from(home_path);

    if cfg!(target_os = "windows") {
        config_dir.push("Lockbox/Config/");
    } else if cfg!(target_os = "macos") {
        config_dir.push("Library/Preferences/Lockbox/");
    } else { // Assuming Linux or other Unix-like OS
        config_dir.push(".config/lockbox/");
    }

    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)?;
    }
    Ok(config_dir)
}