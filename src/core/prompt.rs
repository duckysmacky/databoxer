use crate::{Result, app};
use crate::app::AppMode;

pub fn prompt_password() -> Result<String> {
    match app::get_app_mode() {
        AppMode::CLI => {
            use crate::cli::io::input;
            input::prompt_hidden("Enter the password for the current profile")
        }
        AppMode::GUI => unimplemented!()
    }
}