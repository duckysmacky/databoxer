//! Contains everything related to Databoxer configuration
//! 
//! Provides a base `DataboxerConfig` struct which contains user-defined configuration for the
//! program, which is set to default values on initialization. It is represented as a `config.toml`
//! file on the disk, which is located in the program's default config directory.
//! 
//! Each configuration category is a separate struct (e.g.: `GeneralConfig`). Each field is public
//! for accessing configuration fields

use std::io;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::core::data::io::{read_file, write_file};
use crate::core::error::Result;
use crate::log;

/// Name of the main configuration file
const CONFIG_FILE_NAME: &str = "databoxer.toml";

/// Struct representing a TOML Configuration file
#[derive(Serialize, Deserialize, Debug)]
pub struct DataboxerConfig {
    pub general: GeneralConfig,
    pub encryption: EncryptionConfig,
    pub storage: StorageConfig,
    #[serde(skip)]
    file_path: PathBuf
}

/// Struct containing general configuration for the program
#[derive(Serialize, Deserialize, Debug)]
pub struct GeneralConfig { }

/// Struct containing encryption configuration for the program
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionConfig { }

/// Struct containing storage configuration for the program
#[derive(Serialize, Deserialize, Debug)]
pub struct StorageConfig { }

impl DataboxerConfig {
    /// Imports self from the stored "config.toml" file. In case of the file missing, generates a
    /// new file with the default configuration
    pub fn import(config_directory: PathBuf) -> Result<Self> {
        log!(DEBUG, "Importing Databoxer config");
        let config_file = config_directory.join(CONFIG_FILE_NAME);

        let config = match read_file(&config_file) {
            Ok(file_data) => {
                let mut config: DataboxerConfig = toml::from_str(&file_data)?;
                config.file_path = config_file;
                config
            },
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    log!(INFO, "\"config.toml\" file doesn't exist. Generating new default config");
                    Self::new(config_file)
                } else {
                    return Err(err.into());
                }
            }
        };

        Ok(config)
    }

    /// Bare-minimum constructor to use in case of file not being available to import from
    fn new(
        file_path: PathBuf
    ) -> DataboxerConfig {
        DataboxerConfig {
            general: GeneralConfig { },
            encryption: EncryptionConfig { },
            storage: StorageConfig { },
            file_path
        }
    }

    /// Saves the configuration to the config file
    #[allow(dead_code)]
    pub fn save(&self) -> Result<()> {
        log!(DEBUG, "Saving configuration data to \"config.toml\"");
        let toml_data = toml::to_string(&self)?;

        write_file(&self.file_path, &toml_data, true)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::core::os::data;
    use super::*;

    #[test]
    #[ignore]
    /// Creates the `config.toml` file in the program configuration directory and writes the
    /// default configuration to it
    fn write_default_config() {
        let config_directory = data::get_config_dir().expect("Cannot get config directory");
        let config = DataboxerConfig::import(config_directory);

        assert!(config.is_ok())
    }
}