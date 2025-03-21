//! Contains functions which rely on operating system with their functionality and return values
//! depending on it

use std::path::PathBuf;
use std::{env, fs};
use crate::{new_err, Result};

/// Returns the application data directory based on the OS. Used for storing profiles and other
/// information for program's functionality which is not meant to be edited by the user
pub fn get_data_dir() -> Result<PathBuf> {
    let mut data_dir = get_env_home()?;

    if cfg!(target_os = "windows") {
        data_dir.push("Databoxer/Data/");
    } else if cfg!(target_os = "macos") {
        data_dir.push("Library/Application Support/Databoxer/");
    } else { // Assuming Linux or other Unix-like OS
        data_dir.push(".local/share/databoxer/");
    }

    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }
    Ok(data_dir)
}

/// Returns the application config directory based on the OS. Used for storing configuration files
/// which can be edited by user to change program's functionality
pub fn get_config_dir() -> Result<PathBuf> {
    let mut config_dir = get_env_home()?;
    
    if cfg!(target_os = "windows") {
        config_dir.push("Databoxer/Config/");
    } else if cfg!(target_os = "macos") {
        config_dir.push("Library/Preferences/Databoxer/");
    } else { // Assuming Linux or other Unix-like OS
        config_dir.push(".config/databoxer/");
    }

    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)?;
    }
    Ok(config_dir)
}

/// Returns the "Home" environment variable based on the OS for later file storage. For windows, it
/// is $APPDATA, for others it is $HOME
fn get_env_home() -> Result<PathBuf> {
    let env = {
        if cfg!(target_os = "windows") {
            "APPDATA"
        } else {
            "HOME"
        }
    };
    
    let home_path = env::var(env)
        .map_err(|_| new_err!(OSError: EnvVariableUnavailable, env))?;

    let config_dir = PathBuf::from(home_path);
    Ok(config_dir)
}