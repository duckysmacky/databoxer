mod commands;
mod encryption;
mod logger;
mod storage;

use std::io::{self};
use clap::{command, Arg, ArgAction, Command};

fn main() -> io::Result<()> {
    let args = get_command().get_matches();

    logger::configure_logger(&args);

    // BOX
    if let Some(args) = args.subcommand_matches("box") {
        commands::encrypt(args)
    }

    // UNBOX
    if let Some(args) = args.subcommand_matches("unbox") {
        commands::decrypt(args)
    }

    // KEY
    if let Some(_args) = args.subcommand_matches("key") {
        todo!()
    }

    Ok(())
}

fn get_command() -> Command {
    command!()
        /* BASE COMMAND */
        .arg(Arg::new("debug")
            .short('d')
            .long("debug")
            .action(ArgAction::SetTrue)
            .help("Turns on extensive debug output information")
        )
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Use verbose output (extra information)")
            .action(ArgAction::SetTrue)
            .conflicts_with("quiet")
        )
        .arg(Arg::new("quiet")
            .short('q')
            .long("quiet")
            .help("Do not print any log messages")
            .action(ArgAction::SetTrue)
            .conflicts_with("verbose")
        )
        /* BOX SUBCOMMAND */
        .subcommand(Command::new("box")
            .about("Encrypt specified files into a special file type")
            .arg(Arg::new("path")
                .help("Specify the path(s) to a file or directory for encryption. A file path encrypts the file and a directory path encrypts all files within")
                .default_value(".")
                .action(ArgAction::Append)
            )
            .arg(Arg::new("recursive")
                .short('R')
                .long("recursive")
                .help("Recursively encrypt directory")
                .action(ArgAction::SetTrue)
            )
            .arg(Arg::new("keep-name")
                .short('k')
                .long("keep")
                .help("Keep original file name for the encrypted file")
                .action(ArgAction::SetTrue)
                .conflicts_with("output-path")
            )
            .arg(Arg::new("output-path")
                .short('o')
                .long("output-path")
                .help("Specify a path for the output file. In case of multiple input paths, output paths will be specified in order of the input")
                .action(ArgAction::Append)
            )
            .arg(Arg::new("overwrite") // TODO
                .short('w')
                .long("overwrite")
                .help("Automatically overwrite existing files without prompting the user")
                .action(ArgAction::SetTrue)
            )
            .arg(Arg::new("compression") // TODO
                .short('z')
                .long("compression")
                .help("Compresses the file(s) before encryption")
                .action(ArgAction::Set)
                .default_value("none")
            )
            .arg(Arg::new("exclude") // TODO
                .short('e')
                .long("exclude")
                .help("Exclude specific file patterns from being encrypted")
                .action(ArgAction::Set)
            )
            .arg(Arg::new("preserve-timestamp") // TODO
                .long("preserve-timestamp")
                .help("Retains the original file's timestamp when creating the encrypted file")
                .action(ArgAction::SetTrue)
            )
        )
        /* UNBOX SUBCOMMAND */
        .subcommand(Command::new("unbox")
            .about("Decrypt specified files from a special file type")
            .arg(Arg::new("path")
                .help("Specify the path(s) to a file or directory for encryption. A file path encrypts the file and a directory path encrypts all files within")
                .default_value(".")
                .action(ArgAction::Append)
            )
            .arg(Arg::new("recursive")
                .short('R')
                .long("recursive")
                .help("Recursively decrypt directory")
                .action(ArgAction::SetTrue)
            )
            .arg(Arg::new("output-path")
                .short('o')
                .long("output-path")
                .help("Specify a path for the output file. In case of multiple input paths, output paths will be specified in order of the input")
                .action(ArgAction::Append)
            )
            .arg(Arg::new("overwrite") // TODO
                .short('w')
                .long("overwrite")
                .help("Automatically overwrite existing files without prompting the user")
                .action(ArgAction::SetTrue)
            )
            .arg(Arg::new("check-integrity") // TODO
                .short('i')
                .long("check-integrity")
                .help("Validates the integrity of the decrypted file by comparing it with an original checksum (if available)")
                .action(ArgAction::SetTrue)
            )
            .arg(Arg::new("preserve-attributes") // TODO
                .long("preserve-attributes")
                .help("Preserves original file attributes (e.g., permissions, timestamps) when decrypting")
                .action(ArgAction::SetTrue)
            )
        )
        /* KEY SUBCOMMAND */
        .subcommand(Command::new("key")
            .about("Control encryption keys")
            /* GENERATE KEY SUBCOMMAND */
            .subcommand(Command::new("new")
                .about("Generate a new encryption key")
                .aliases(["generate", "gen"])
            )
            /* REMOVE KEY SUBCOMMAND */
            .subcommand(Command::new("delete")
                .about("Delete old encryption key")
                .aliases(["del", "remove", "reset"])
            )
        )
}