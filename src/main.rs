//! Databoxer entry point

use databoxer::app::{self, AppMode};
use databoxer::cli;

fn main() {
    let args = std::env::args();
    
    if args.len() < 2 {
        // Launch GUI
        app::set_app_mode(AppMode::GUI);
        unimplemented!()
    } else {
        // Launch CLI
        app::set_app_mode(AppMode::CLI);
        cli::run();
    }
}