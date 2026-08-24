use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub struct BoxArgs {
    /// Specify the path(s) to a file or directory for encryption. A file path encrypts the file and a directory path encrypts all files within
    #[arg(default_value = ".")]
    pub path: Vec<PathBuf>,

    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,

    /// Recursively encrypt directory
    #[arg(short = 'R', long)]
    pub recursive: bool,

    /// Keep original file name for the encrypted file
    #[arg(short = 'k', long, conflicts_with = "output")]
    pub keep_name: bool,

    /// Specify a path for the output file. In case of multiple input paths, output paths will be specified in order of the input
    #[arg(short, long, conflicts_with = "keep_name")]
    pub output: Vec<PathBuf>,

    /// Output the full relative path to the encrypted file
    #[arg(short = 'f', long)]
    pub show_full_path: bool,

    /// Disable random padding generation for the .box file
    #[arg(long)]
    pub no_padding: bool,

    /// Encrypt original file metadata (name, extension, OS, modify time, etc.)
    #[arg(short = 'm', long = "metadata")]
    pub encrypt_metadata: bool,
}
