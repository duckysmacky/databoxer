//! CLI implementation of `databoxer_core::io::log::Logger`

use std::fmt;

use databoxer_core::io::log::{Logger, LogType};

/// Modes which `CliLogger` can use, controlling how much gets printed
pub enum LoggerMode {
    QUIET,
    NORMAL,
    VERBOSE,
}

/// Responsible for printing diagnostic log messages to `stderr`, having three main modes: quiet,
/// normal and verbose, each displaying different levels of information: none, only needed and
/// everything respectively. Also has a debug side-mode which outputs debug information
pub struct CliLogger {
    debug: bool,
    mode: LoggerMode,
}

impl CliLogger {
    pub fn new(debug: bool, mode: LoggerMode) -> Self {
        CliLogger { debug, mode }
    }
}

impl Logger for CliLogger {
    /// Uses the log type and own set mode to determine whether the message should be logged,
    /// always printing to `stderr`
    fn log(&self, log_type: LogType, message: fmt::Arguments<'_>) {
        use LogType::*;

        if self.debug && log_type == DEBUG {
            eprintln!("[{}] {}", log_type.icon(), message);
            return;
        }

        let should_log = match self.mode {
            LoggerMode::QUIET => log_type == ERROR,
            LoggerMode::NORMAL => matches!(log_type, ERROR | WARN),
            LoggerMode::VERBOSE => true,
        };

        if should_log {
            eprintln!("[{}] {}", log_type.icon(), message);
        }
    }
}
