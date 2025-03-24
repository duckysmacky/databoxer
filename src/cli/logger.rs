//! Contains logic and types for CLI-specific logging

use std::fmt;
use std::sync::{Arc, Mutex};
use clap::ArgMatches;
use lazy_static::lazy_static;
use crate::core::logs::LogType;

lazy_static! {
    pub static ref LOGGER: Arc<Mutex<Logger>> = Arc::new(Mutex::new(Logger::new()));
}

/// Enum representing modes which Logger can use
enum LoggerMode {
    QUIET,
    NORMAL,
    VERBOSE,
}

/// Logger is responsible for the CLI logging, having three main modes: quiet, normal and verbose, 
/// each displaying different levels of information: none, only needed and everything respectively.
/// Also has a debug side-mode which outputs debug information 
pub struct Logger {
    debug: bool,
    mode: LoggerMode
}

impl Logger {
    pub fn new() -> Self {
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

/// Initiates and configures logger to be of one the modes based on the command arguments to be
/// later used for CLI logging
pub fn configure_logger(args: &ArgMatches) {
    let mut logger = LOGGER.lock().unwrap();
    logger.debug = args.get_flag("DEBUG");
    logger.mode = {
        if args.get_flag("QUIET") {
            LoggerMode::QUIET
        } else if args.get_flag("VERBOSE") {
            LoggerMode::VERBOSE
        } else {
            LoggerMode::NORMAL
        }
    };
}

/// Macro used for better data output. Acts like a wrapper above print! in order to produce a
/// more suitable output based on the logger mode (cleaner and simpler output when in quiet mode).
/// Add the `list` keyword to suggest that the data provided should be outputted as a list
#[macro_export]
macro_rules! output {
    (list $($args:tt)*) => {
        {
            use crate::cli::logger::LOGGER;
            let logger = LOGGER.lock().unwrap();
            logger.output(true, format_args!($($args)*));
        }
    };
    ($($args:tt)*) => {
        {
            use crate::cli::logger::LOGGER;
            let logger = LOGGER.lock().unwrap();
            logger.output(false, format_args!($($args)*));
        }
    };
}
