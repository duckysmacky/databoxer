//! CLI implementation of `databoxer_core::io::log::LogSink`

use std::fmt;
use clap::ArgMatches;
use databoxer_core::io::log::{LogSink, LogType};

/// Modes which `CliLogSink` can use, controlling how much gets printed
pub enum LoggerMode {
    QUIET,
    NORMAL,
    VERBOSE,
}

/// Responsible for the console logging, having three main modes: quiet, normal and verbose,
/// each displaying different levels of information: none, only needed and everything
/// respectively. Also has a debug side-mode which outputs debug information
pub struct CliLogSink {
    debug: bool,
    mode: LoggerMode,
}

impl CliLogSink {
    pub fn new(args: &ArgMatches) -> Self {
        CliLogSink {
            debug: args.get_flag("DEBUG"),
            mode: {
                if args.get_flag("QUIET") {
                    LoggerMode::QUIET
                } else if args.get_flag("VERBOSE") {
                    LoggerMode::VERBOSE
                } else {
                    LoggerMode::NORMAL
                }
            },
        }
    }
}

impl LogSink for CliLogSink {
    /// Uses the log type and own set mode to determine whether the message should be logged and
    /// outputs it to the `stdout` or `stderr` respectively
    fn log(&self, log_type: LogType, message: fmt::Arguments<'_>) {
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
    fn output(&self, list: bool, data: fmt::Arguments<'_>) {
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
