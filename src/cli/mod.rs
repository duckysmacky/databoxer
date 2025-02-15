//! Contains everything related to the CLI wrapper around the Databoxer API

use std::time::Instant;

pub mod logger;
pub mod io;
mod handlers;
mod command;

pub fn run() {
    let global_args = &command::get_command().get_matches();

    logger::configure_logger(&global_args);

    /* BOX */
    if let Some(args) = global_args.subcommand_matches("box") {
        let start_time = Instant::now();
        let (total, error) = handlers::handle_box(args);

        let duration = start_time.elapsed();
        println!("[{}/{}] files encrypted", total - error, total);
        println!("Total time taken: {:.2?}", duration);

        if total == error {
            std::process::exit(1);
        }
    }

    /* UNBOX */
    if let Some(args) = global_args.subcommand_matches("unbox") {
        let start_time = Instant::now();
        let (total, error) = handlers::handle_unbox(args);

        let duration = start_time.elapsed();
        println!("[{}/{}] files decrypted", total - error, total);
        println!("Total time taken: {:.2?}", duration);

        if total == error {
            std::process::exit(1);
        }
    }

    /* INFORMATION */
    if let Some(args) = global_args.subcommand_matches("information") {
        handlers::handle_information(args);
    }

    /* PROFILE */
    if let Some(args) = global_args.subcommand_matches("profile") {
        /* PROFILE CREATE */
        if let Some(args) = args.subcommand_matches("new") {
            handlers::handle_profile_create(args);
        }
        /* PROFILE DELETE */
        if let Some(args) = args.subcommand_matches("delete") {
            handlers::handle_profile_delete(args);
        }
        /* PROFILE SET */
        if let Some(args) = args.subcommand_matches("set") {
            handlers::handle_profile_set(args);
        }
        /* PROFILE GET */
        if let Some(args) = args.subcommand_matches("get") {
            handlers::handle_profile_get(args);
        }
        /* PROFILE LIST */
        if let Some(args) = args.subcommand_matches("list") {
            handlers::handle_profile_list(args);
        }
    }

    /* KEY */
    if let Some(args) = global_args.subcommand_matches("key") {
        /* KEY NEW */
        if let Some(args) = args.subcommand_matches("new") {
            handlers::handle_key_new(args);
        }
        /* KEY GET */
        if let Some(args) = args.subcommand_matches("get") {
            handlers::handle_key_get(args);
        }
        /* KEY SET */
        if let Some(args) = args.subcommand_matches("set") {
            handlers::handle_key_set(args);
        }
    }
}