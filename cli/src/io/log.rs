//! Contains logic for configuring the shared core logger based on CLI arguments, and the
//! `output!` macro for structured plain-data output

use clap::ArgMatches;
use databoxer_core::io::log::{self, LoggerMode};

/// Initiates and configures the shared logger to be of one the modes based on the command
/// arguments to be later used for CLI logging
pub fn configure_logger(args: &ArgMatches) {
    log::set_debug(args.get_flag("DEBUG"));
    log::set_mode({
        if args.get_flag("QUIET") {
            LoggerMode::QUIET
        } else if args.get_flag("VERBOSE") {
            LoggerMode::VERBOSE
        } else {
            LoggerMode::NORMAL
        }
    });
}

/// Macro used for better data output. Acts like a wrapper above print! in order to produce a
/// more suitable output based on the logger mode (cleaner and simpler output when in quiet mode).
/// Add the `list` keyword to suggest that the data provided should be outputted as a list
#[macro_export]
macro_rules! output {
    (list $($args:tt)*) => {
        {
            use databoxer_core::io::log::LOGGER;
            let logger = LOGGER.lock().unwrap();
            logger.output(true, format_args!($($args)*));
        }
    };
    ($($args:tt)*) => {
        {
            use databoxer_core::io::log::LOGGER;
            let logger = LOGGER.lock().unwrap();
            logger.output(false, format_args!($($args)*));
        }
    };
}
