//! Databoxer entry point

use std::process;

fn main() {
    let args = std::env::args();

    if args.len() < 2 {
        println!("GUI not available yet. For the full list of available CLI commands use --help");
        process::exit(-1);
    } else {
        let code = databoxer_cli::run();
        process::exit(code);
    }
}
