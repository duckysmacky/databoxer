use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommands,
}

#[derive(Debug, Subcommand)]
pub enum KeyCommands {
    /// Generate a new encryption key for the current profile
    #[command(alias = "generate")]
    New(KeyNewArgs),

    /// Get current profile's encryption key
    Get(KeyGetArgs),

    /// Set a new key for the current profile
    Set(KeySetArgs),
}

#[derive(Debug, Args)]
pub struct KeyNewArgs {
    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeyGetArgs {
    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,

    /// Output key as an array of bytes
    #[arg(short = 'b', long = "byte-array")]
    pub as_byte_array: bool,
}

#[derive(Debug, Args)]
pub struct KeySetArgs {
    /// A 32-byte encryption key represented by hex values
    #[arg(required_unless_present = "file")]
    pub key: Option<String>,

    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,

    /// Specify the file from which the 32-byte key value should be read
    #[arg(short = 'f', long)]
    pub file: Option<PathBuf>,
}
