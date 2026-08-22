use serde::{Deserialize, Serialize};

pub mod data;

/// Enum representing one of the possible operating systems
#[derive(Serialize, Deserialize, Debug)]
pub enum OS {
    WINDOWS, MACOS, LINUX, OTHER
}

impl OS {
    /// Fetches current operating system and returns it as an `OS` enum
    pub fn get() -> Self {
        let os = std::env::consts::OS;
        match os {
            "windows" => OS::WINDOWS,
            "macos" => OS::MACOS,
            "linux" => OS::LINUX,
            _ => OS::OTHER,
        }
    }

    /// Checks whether this is a Unix-like OS
    pub fn is_unix(&self) -> bool {
        matches!(self, OS::MACOS | OS::LINUX)
    }
}
