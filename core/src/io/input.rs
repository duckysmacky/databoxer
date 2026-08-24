use std::{io, sync::OnceLock};

/// Implemented by whichever frontend embeds this crate (CLI, GUI, ...) to supply ways of
/// getting text input from the user
pub trait InputPrompter: Send + Sync {
    /// Prompts for a single line of visible input
    fn prompt_line(&self, message: &str) -> io::Result<String>;
    /// Prompts for multiple lines of visible input, ending on a blank line
    fn prompt_lines(&self, message: &str) -> io::Result<Vec<String>>;
    /// Prompts for a single line of hidden (masked) input, e.g. a password
    fn prompt_hidden(&self, message: &str) -> io::Result<String>;
}

static INPUT_PROMPTER: OnceLock<Box<dyn InputPrompter>> = OnceLock::new();

/// Registers the input prompter used by `prompt_line`/`prompt_lines`/`prompt_hidden`. Should
/// be called once during startup, before any function that may need user input
pub fn set_input_prompter(prompter: Box<dyn InputPrompter>) {
    INPUT_PROMPTER.set(prompter).ok();
}

fn prompter() -> &'static dyn InputPrompter {
    INPUT_PROMPTER
        .get()
        .expect("Input prompter not set")
        .as_ref()
}

/// Prompts the user for a single line of input
pub fn prompt_line(message: &str) -> io::Result<String> {
    prompter().prompt_line(message)
}

/// Prompts the user for multiple lines of input, ending on a blank line
pub fn prompt_lines(message: &str) -> io::Result<Vec<String>> {
    prompter().prompt_lines(message)
}

/// Prompts the user for a single line of hidden input, such as a password
pub fn prompt_hidden(message: &str) -> io::Result<String> {
    prompter().prompt_hidden(message)
}
