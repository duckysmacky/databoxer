use std::sync::OnceLock;
use crate::{Result, new_err};

/// Implemented by whichever frontend embeds this crate (CLI, GUI, ...) to supply a way of
/// asking the user for a password
pub trait PasswordPrompter: Send + Sync {
    fn prompt_password(&self, message: &str) -> std::io::Result<String>;
}

static PASSWORD_PROMPTER: OnceLock<Box<dyn PasswordPrompter>> = OnceLock::new();

/// Registers the password prompter to be used by `prompt_password`. Should be called once
/// during startup, before any function that may need to prompt for a password
pub fn set_password_prompter(prompter: Box<dyn PasswordPrompter>) {
    PASSWORD_PROMPTER.set(prompter).ok();
}

pub fn prompt_password() -> Result<String> {
    let prompter = PASSWORD_PROMPTER.get()
        .ok_or_else(|| new_err!(IOError: StandardIO; "No password prompter registered"))?;
    prompter.prompt_password("Enter the password for the current profile")
        .map_err(|e| new_err!(IOError: StandardIO; e))
}
