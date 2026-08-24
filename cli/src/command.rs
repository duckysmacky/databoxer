//! Typed command-line interface definitions.

mod r#box;
mod info;
mod key;
mod profile;
mod unbox;

pub use {
    info::InfoArgs,
    key::{KeyArgs, KeyCommands, KeyGetArgs, KeyNewArgs, KeySetArgs},
    profile::{ProfileArgs, ProfileCommands, ProfileDeleteArgs, ProfileNewArgs, ProfileSetArgs},
    r#box::BoxArgs,
    unbox::UnboxArgs,
};

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Turns on debug output information
    #[arg(short, long, global = true)]
    pub debug: bool,

    /// Use verbose output
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Use quiet output
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Encrypt specified files into a special file type
    Box(BoxArgs),

    /// Decrypt specified files from a special file type
    Unbox(UnboxArgs),

    /// Parse and get original file information from a '.box' file
    Info(InfoArgs),

    /// Control custom profiles
    Profile(ProfileArgs),

    /// Control profile's encryption key
    Key(KeyArgs),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::{CommandFactory, Parser};

    use super::*;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_command_is_left_for_application_error_handling() {
        let cli = Cli::try_parse_from(["databoxer"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn box_defaults_and_legacy_option_names_are_preserved() {
        let cli = Cli::try_parse_from(["databoxer", "box", "--full", "--metadata"]).unwrap();
        let Some(Commands::Box(args)) = cli.command else {
            panic!("expected box command");
        };

        assert_eq!(args.path, vec![PathBuf::from(".")]);
        assert!(args.show_full_path);
        assert!(args.encrypt_metadata);
    }

    #[test]
    fn global_flags_are_accepted_after_subcommands() {
        let cli = Cli::try_parse_from(["databoxer", "key", "get", "--verbose"]).unwrap();
        assert!(cli.verbose);
        assert!(matches!(
            cli.command,
            Some(Commands::Key(KeyArgs {
                command: KeyCommands::Get(_)
            }))
        ));
    }

    #[test]
    fn profile_aliases_are_preserved() {
        let aliases = [
            ("create", "new"),
            ("remove", "delete"),
            ("select", "set"),
            ("current", "get"),
        ];

        for (alias, expected) in aliases {
            let mut argv = vec!["databoxer", "profile", alias];
            if !matches!(alias, "current") {
                argv.push("example");
            }
            let cli = Cli::try_parse_from(argv).unwrap();
            let Some(Commands::Profile(args)) = cli.command else {
                panic!("expected profile command");
            };

            let actual = match args.command {
                ProfileCommands::New(_) => "new",
                ProfileCommands::Delete(_) => "delete",
                ProfileCommands::Set(_) => "set",
                ProfileCommands::Get => "get",
                ProfileCommands::List => "list",
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn key_generate_alias_is_preserved() {
        let cli = Cli::try_parse_from(["databoxer", "key", "generate"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Key(KeyArgs {
                command: KeyCommands::New(_)
            }))
        ));
    }

    #[test]
    fn builder_constraints_are_preserved() {
        assert!(Cli::try_parse_from(["databoxer", "--verbose", "--quiet"]).is_err());
        assert!(
            Cli::try_parse_from(["databoxer", "box", "--keep-name", "--output", "out.box",])
                .is_err()
        );
        assert!(Cli::try_parse_from(["databoxer", "key", "set"]).is_err());
        assert!(Cli::try_parse_from(["databoxer", "profile"]).is_err());
        assert!(Cli::try_parse_from(["databoxer", "key"]).is_err());
    }

    #[test]
    fn repeated_paths_and_outputs_keep_their_order() {
        let cli = Cli::try_parse_from([
            "databoxer",
            "box",
            "first",
            "second",
            "--output",
            "one.box",
            "--output",
            "two.box",
        ])
        .unwrap();
        let Some(Commands::Box(args)) = cli.command else {
            panic!("expected box command");
        };

        assert_eq!(args.path, [PathBuf::from("first"), PathBuf::from("second")]);
        assert_eq!(
            args.output,
            [PathBuf::from("one.box"), PathBuf::from("two.box")]
        );
    }
}
