//! Contains app-wide information and states, like run modes

use std::sync::OnceLock;

#[derive(Clone, PartialEq)]
pub enum AppMode {
    CLI,
    GUI,
}

static APP_MODE: OnceLock<AppMode> = OnceLock::new();

pub fn set_app_mode(mode: AppMode) {
    APP_MODE.set(mode).ok();
}

pub fn get_app_mode<'a>() -> &'a AppMode { 
    APP_MODE.get().unwrap_or(&AppMode::CLI)
}