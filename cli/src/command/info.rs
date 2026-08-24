use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub struct InfoArgs {
    /// Specify the target encrypted '.box' file
    pub path: PathBuf,

    /// Show unknown metadata
    #[arg(short = 'u', long)]
    pub show_unknown: bool,
}
