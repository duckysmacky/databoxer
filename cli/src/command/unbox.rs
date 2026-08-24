use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub struct UnboxArgs {
    /// Specify the path(s) to a file or directory for encryption. A file path encrypts the file and a directory path encrypts all files within
    #[arg(default_value = ".")]
    pub path: Vec<PathBuf>,

    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,

    /// Recursively decrypt directory
    #[arg(short = 'R', long)]
    pub recursive: bool,

    /// Specify a path for the output file. In case of multiple input paths, output paths will be specified in order of the input
    #[arg(short, long)]
    pub output: Vec<PathBuf>,

    /// Output the full relative path to the decrypted file
    #[arg(short = 'f', long = "full")]
    pub show_full_path: bool,
}
