//! Contains everything related to the CLI wrapper around the Databoxer API

use std::time::Instant;
use databoxer_core::log;

pub mod logger;
pub mod io;

mod handlers;
mod command;
mod path;

/// Runs the CLI application, handling subcommands and their arguments. Returns an exit code.
pub fn run() -> i32 {
    let global_args = &command::get_command().get_matches();

    logger::configure_logger(&global_args);

    /* BOX */
    if let Some(args) = global_args.subcommand_matches("box") {
        let start_time = Instant::now();
        let (total, successful, code) = handlers::handle_box(args);

        let duration = start_time.elapsed();
        log!(STATUS, "[{}/{}] files encrypted", successful, total);
        log!(STATUS, "Total time taken: {:.2?}", duration);

        return code;
    }

    /* UNBOX */
    if let Some(args) = global_args.subcommand_matches("unbox") {
        let start_time = Instant::now();
        let (total, successful, code) = handlers::handle_unbox(args);

        let duration = start_time.elapsed();
        log!(STATUS, "[{}/{}] files decrypted", successful, total);
        log!(STATUS, "Total time taken: {:.2?}", duration);

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
    
    -1
}