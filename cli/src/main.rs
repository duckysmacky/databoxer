//! Databoxer entry point

use std::{time::Instant, process};

use clap::ArgMatches;

use databoxer_cli::{command, error::{self, CliError}, handlers, io, output};

fn main() {
    let global_args = &command::get_command().get_matches();
    
    let debug_mode = global_args.get_flag("DEBUG");
    let logger_mode = if global_args.get_flag("QUIET") {
        io::log::LoggerMode::QUIET
    } else if global_args.get_flag("VERBOSE") {
        io::log::LoggerMode::VERBOSE
    } else {
        io::log::LoggerMode::NORMAL
    };

    databoxer_core::io::log::set_logger(Box::new(io::log::CliLogger::new(debug_mode, logger_mode)));
    databoxer_core::io::input::set_input_prompter(Box::new(io::input::CliInputPrompter));

    let code = run(global_args);
    process::exit(code);
}

/// Runs the CLI application, handling subcommands and their arguments. Returns an exit code.
pub fn run(global_args: &ArgMatches) -> i32 {
    /* BOX */
    if let Some(args) = global_args.subcommand_matches("box") {
        let start_time = Instant::now();
        let (total, successful, code) = handlers::handle_box(args);

        let duration = start_time.elapsed();
        output!(SUCCESS, "[{}/{}] files encrypted", successful, total);
        output!(SUCCESS, "Total time taken: {:.2?}", duration);

        return code;
    }

    /* UNBOX */
    if let Some(args) = global_args.subcommand_matches("unbox") {
        let start_time = Instant::now();
        let (total, successful, code) = handlers::handle_unbox(args);

        let duration = start_time.elapsed();
        output!(SUCCESS, "[{}/{}] files decrypted", successful, total);
        output!(SUCCESS, "Total time taken: {:.2?}", duration);

        return code;
    }

    /* INFORMATION */
    if let Some(args) = global_args.subcommand_matches("info") {
        handlers::handle_info(args);
        return error::SUCCESS;
    }

    /* PROFILE */
    if let Some(args) = global_args.subcommand_matches("profile") {
        /* PROFILE CREATE */
        if let Some(args) = args.subcommand_matches("new") {
            handlers::handle_profile_create(args);
            return error::SUCCESS;
        }
        /* PROFILE DELETE */
        if let Some(args) = args.subcommand_matches("delete") {
            handlers::handle_profile_delete(args);
            return error::SUCCESS;
        }
        /* PROFILE SET */
        if let Some(args) = args.subcommand_matches("set") {
            handlers::handle_profile_set(args);
            return error::SUCCESS;
        }
        /* PROFILE GET */
        if let Some(args) = args.subcommand_matches("get") {
            handlers::handle_profile_get(args);
            return error::SUCCESS;
        }
        /* PROFILE LIST */
        if let Some(args) = args.subcommand_matches("list") {
            handlers::handle_profile_list(args);
            return error::SUCCESS;
        }
    }

    /* KEY */
    if let Some(args) = global_args.subcommand_matches("key") {
        /* KEY NEW */
        if let Some(args) = args.subcommand_matches("new") {
            handlers::handle_key_new(args);
            return error::SUCCESS;
        }
        /* KEY GET */
        if let Some(args) = args.subcommand_matches("get") {
            handlers::handle_key_get(args);
            return error::SUCCESS;
        }
        /* KEY SET */
        if let Some(args) = args.subcommand_matches("set") {
            handlers::handle_key_set(args);
            return error::SUCCESS;
        }
    }

    error::fail(&CliError::NoCommand)
}
