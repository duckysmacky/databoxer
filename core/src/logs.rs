use std::fmt;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;

#[derive(PartialEq)]
pub enum LogType {
    INFO,
    STATUS,
    SUCCESS,
    WARN,
    ERROR,
    DEBUG,
    INPUT,
}

impl LogType {
    pub fn icon<'a>(&self) -> &'a str {
        match self {
            LogType::INFO => "i",
            LogType::STATUS => "*",
            LogType::SUCCESS => "+",
            LogType::WARN => "!",
            LogType::ERROR => "-",
            LogType::DEBUG => "d",
            LogType::INPUT => "?",
        }
    }
}

/// Modes which the `Logger` can use, controlling how much gets printed
pub enum LoggerMode {
    QUIET,
    NORMAL,
    VERBOSE,
}

/// Logger is responsible for the console logging, having three main modes: quiet, normal and
/// verbose, each displaying different levels of information: none, only needed and everything
/// respectively. Also has a debug side-mode which outputs debug information
pub struct Logger {
    debug: bool,
    mode: LoggerMode,
}

impl Logger {
    fn new() -> Self {
        Logger {
            debug: false,
            mode: LoggerMode::NORMAL,
        }
    }

    /// Uses the log type and own set mode to determine whether the message should be logged and
    /// outputs it to the `stdout` or `stderr` respectively
    pub fn log(&self, log_type: LogType, message: fmt::Arguments<'_>) {
        use LogType::*;

        if self.debug && log_type == DEBUG {
            println!("[{}] {}", log_type.icon(), message);
            return;
        }

        match self.mode {
            LoggerMode::QUIET => {
                return;
            },
            LoggerMode::NORMAL => {
                match log_type {
                    ERROR | WARN => eprintln!("[{}] {}", log_type.icon(), message),
                    SUCCESS | STATUS => println!("[{}] {}", log_type.icon(), message),
                    _ => return
                }
            },
            LoggerMode::VERBOSE => {
                match log_type {
                    ERROR | WARN => eprintln!("[{}] {}", log_type.icon(), message),
                    _ => println!("[{}] {}", log_type.icon(), message)
                }
            },
        }
    }

    /// Outputs plain data to the `stdout` based on the logger type. If set to quite mode, will
    /// output a clean, decoration-free string, else will format it. `true` or `false` should be
    /// provided as the first argument to imply that the data provided should be outputted as a
    /// list or not
    pub fn output(&self, list: bool, data: fmt::Arguments<'_>) {
        match self.mode {
            LoggerMode::QUIET => {
                println!("{}", data);
            },
            _ => {
                if list {
                    println!(" - {}", data);
                } else {
                    println!("\t{}", data);
                }
            }
        }
    }
}

lazy_static! {
    pub static ref LOGGER: Arc<Mutex<Logger>> = Arc::new(Mutex::new(Logger::new()));
}

/// Sets whether debug-level messages should be printed
pub fn set_debug(enabled: bool) {
    LOGGER.lock().unwrap().debug = enabled;
}

/// Sets the logger's verbosity mode
pub fn set_mode(mode: LoggerMode) {
    LOGGER.lock().unwrap().mode = mode;
}

/// Macro used for logging messages throughout the program. Acts like a wrapper above the shared
/// `Logger`, formatting the message based on the log type and the logger's current mode
#[macro_export]
macro_rules! log {
    ($log_type:ident, $($arg:tt)*) => {
        $crate::logs::LOGGER.lock().unwrap().log($crate::logs::LogType::$log_type, format_args!($($arg)*))
    };
}
