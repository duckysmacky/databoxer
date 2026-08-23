//! Databoxer entry point

use std::process;

fn main() {
    databoxer_core::io::input::set_password_prompter(Box::new(databoxer_cli::io::input::CliPasswordPrompter));

    let code = databoxer_cli::run();

    process::exit(code);
}
