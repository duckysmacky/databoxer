use crate::{Result, app, new_err};
use crate::app::AppMode;

pub fn prompt_password() -> Result<String> {
    match app::get_app_mode() {
        AppMode::CLI => {
            use crate::cli::io::input;
            input::prompt_hidden("Enter the password for the current profile")
                .map_err(|e| new_err!(IOError: StandardIO; e))
        }
        AppMode::GUI => unimplemented!()
    }
}