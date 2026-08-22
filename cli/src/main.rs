//! Databoxer entry point

use std::process;

fn main() {
    databoxer_core::prompt::set_password_prompter(Box::new(databoxer_cli::io::CliPasswordPrompter));

    let code = databoxer_cli::run();

    process::exit(code);
}
