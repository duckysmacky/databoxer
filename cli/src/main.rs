//! Databoxer entry point

use std::process;

fn main() {
    databoxer_core::io::input::set_input_prompter(Box::new(databoxer_cli::io::input::CliInputPrompter));

    let code = databoxer_cli::run();

    process::exit(code);
}
