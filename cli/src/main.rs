//! Databoxer entry point

use std::{time::Instant, process};

use clap::ArgMatches;

use databoxer_cli::{command, error, handlers, io, output};

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
        return handlers::handle_info(args);
    }

    /* PROFILE */
    if let Some(args) = global_args.subcommand_matches("profile") {
        /* PROFILE CREATE */
        if let Some(args) = args.subcommand_matches("new") {
            return handlers::handle_profile_create(args);
        }
        /* PROFILE DELETE */
        if let Some(args) = args.subcommand_matches("delete") {
            return handlers::handle_profile_delete(args);
        }
        /* PROFILE SET */
        if let Some(args) = args.subcommand_matches("set") {
            return handlers::handle_profile_set(args);
        }
        /* PROFILE GET */
        if let Some(args) = args.subcommand_matches("get") {
            return handlers::handle_profile_get(args);
        }
        /* PROFILE LIST */
        if let Some(args) = args.subcommand_matches("list") {
            return handlers::handle_profile_list(args);
        }
    }

    /* KEY */
    if let Some(args) = global_args.subcommand_matches("key") {
        /* KEY NEW */
        if let Some(args) = args.subcommand_matches("new") {
            return handlers::handle_key_new(args);
        }
        /* KEY GET */
        if let Some(args) = args.subcommand_matches("get") {
            return handlers::handle_key_get(args);
        }
        /* KEY SET */
        if let Some(args) = args.subcommand_matches("set") {
            return handlers::handle_key_set(args);
        }
    }

    error::CLI_FAILURE
}
