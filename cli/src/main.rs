//! Databoxer CLI entry point

use std::{process, time::Instant};

use clap::Parser;

use databoxer_core::setup as core_setup;
use databoxer_cli::{
    command::{Cli, Commands, KeyCommands, ProfileCommands},
    error::{self, CliError},
    handlers, io, output,
};

fn main() {
    let cli = Cli::parse();

    let logger_mode = if cli.quiet {
        io::log::LoggerMode::QUIET
    } else if cli.verbose {
        io::log::LoggerMode::VERBOSE
    } else {
        io::log::LoggerMode::NORMAL
    };

    core_setup::set_hooks(core_setup::FrontendHooks {
        logger: Box::new(io::log::CliLogger::new(cli.debug, logger_mode)),
        prompter: Box::new(io::input::CliInputPrompter),
    });

    process::exit(run(cli.command.as_ref()));
}

/// Runs the CLI application, handling a parsed command and returning an exit code.
pub fn run(command: Option<&Commands>) -> i32 {
    match command {
        Some(Commands::Box(args)) => {
            let start_time = Instant::now();
            let (total, successful, code) = handlers::handle_box(args);

            output!(SUCCESS, "[{}/{}] files encrypted", successful, total);
            output!(SUCCESS, "Total time taken: {:.2?}", start_time.elapsed());
            code
        }
        Some(Commands::Unbox(args)) => {
            let start_time = Instant::now();
            let (total, successful, code) = handlers::handle_unbox(args);

            output!(SUCCESS, "[{}/{}] files decrypted", successful, total);
            output!(SUCCESS, "Total time taken: {:.2?}", start_time.elapsed());
            code
        }
        Some(Commands::Info(args)) => {
            handlers::handle_info(args);
            error::SUCCESS
        }
        Some(Commands::Profile(args)) => {
            match &args.command {
                ProfileCommands::New(args) => handlers::handle_profile_create(args),
                ProfileCommands::Delete(args) => handlers::handle_profile_delete(args),
                ProfileCommands::Set(args) => handlers::handle_profile_set(args),
                ProfileCommands::Get => handlers::handle_profile_get(),
                ProfileCommands::List => handlers::handle_profile_list(),
            }
            error::SUCCESS
        }
        Some(Commands::Key(args)) => {
            match &args.command {
                KeyCommands::New(args) => handlers::handle_key_new(args),
                KeyCommands::Get(args) => handlers::handle_key_get(args),
                KeyCommands::Set(args) => handlers::handle_key_set(args),
            }
            error::SUCCESS
        }
        None => error::fail(&CliError::NoCommand),
    }
}
