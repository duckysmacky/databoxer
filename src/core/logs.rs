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

#[macro_export]
macro_rules! log {
    ($log_type:ident: $($arg:tt)*) => {
        {
            use crate::core::logs::LogType::*;
            match crate::app::get_app_mode() {
                AppMode::CLI => {
                    let logger = crate::cli::logger::LOGGER.lock().unwrap();
                    logger.log(LogType::$log_type, format_args!($($arg)*));
                }
                AppMode::GUI => {
                    unimplemented!()
                }
            }
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        {
            use crate::cli::logger::LOGGER;
            use crate::core::logs::LogType;
            let logger = LOGGER.lock().unwrap();
            logger.log(LogType::INFO, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        {
            use crate::cli::logger::LOGGER;
            use crate::core::logs::LogType;
            let logger = LOGGER.lock().unwrap();
            logger.log(LogType::WARN, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {
        {
            use crate::cli::logger::LOGGER;
            use crate::core::logs::LogType;
            let logger = LOGGER.lock().unwrap();
            logger.log(LogType::SUCCESS, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        {
            use crate::cli::logger::LOGGER;
            use crate::core::logs::LogType;
            let logger = LOGGER.lock().unwrap();
            logger.log(LogType::ERROR, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        {
            use crate::cli::logger::LOGGER;
            use crate::core::logs::LogType;
            let logger = LOGGER.lock().unwrap();
            logger.log(LogType::DEBUG, format_args!($($arg)*));
        }
    }
}