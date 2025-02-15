//! Databoxer entry point

use std::process;
use databoxer::app::{self, AppMode};
use databoxer::cli;

fn main() {
    let args = std::env::args();
    
    if args.len() < 2 {
        // Launch GUI
        app::set_app_mode(AppMode::GUI);
        println!("GUI not available yet. For the full list of available CLI commands use --help");
        process::exit(1);
    } else {
        // Launch CLI
        app::set_app_mode(AppMode::CLI);
        cli::run();
    }
}