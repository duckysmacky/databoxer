use std::{sync::OnceLock, fmt};

#[derive(PartialEq)]
pub enum LogType {
    INFO,
    WARN,
    ERROR,
    DEBUG,
}

impl LogType {
    pub fn icon(&self) -> &'static str {
        match self {
            LogType::INFO => "i",
            LogType::WARN => "!",
            LogType::ERROR => "-",
            LogType::DEBUG => "d",
        }
    }
}

/// Implemented by whichever frontend embeds this crate (CLI, GUI, ...) to receive diagnostic
/// log messages
pub trait Logger: Send + Sync {
    fn log(&self, log_type: LogType, message: fmt::Arguments);
}

pub static LOGGER: OnceLock<Box<dyn Logger>> = OnceLock::new();

/// Registers the logger used by `log!`. Should be called once during startup
pub fn set_logger(logger: Box<dyn Logger>) {
    LOGGER.set(logger).ok();
}

/// Macro used for logging diagnostic messages throughout the program (status, warnings, errors,
/// debug info - not program output). Dispatches to the registered `Logger`, or does nothing if
/// none has been registered yet
#[macro_export]
macro_rules! log {
    ($log_type:ident, $($arg:tt)*) => {
        if let Some(logger) = $crate::io::log::LOGGER.get() {
            logger.log($crate::io::log::LogType::$log_type, format_args!($($arg)*));
        }
    };
}
