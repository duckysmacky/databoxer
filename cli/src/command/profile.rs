use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub command: ProfileCommands,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    /// Create a new profile
    #[command(alias = "create")]
    New(ProfileNewArgs),

    /// Delete a specified profile
    #[command(alias = "remove")]
    Delete(ProfileDeleteArgs),

    /// Select a profile to use
    #[command(alias = "select")]
    Set(ProfileSetArgs),

    /// Get current profile's name
    #[command(alias = "current")]
    Get,

    /// List all available profiles (names)
    List,
}

#[derive(Debug, Args)]
pub struct ProfileNewArgs {
    /// A unique name for the profile
    pub name: String,

    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct ProfileDeleteArgs {
    /// Name of the profile to delete
    pub name: String,

    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct ProfileSetArgs {
    /// Name of the profile to switch to
    pub name: String,

    /// Specify the password used for authentication
    #[arg(short, long)]
    pub password: Option<String>,
}
