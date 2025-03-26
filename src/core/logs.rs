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
    ($log_type:ident, $($arg:tt)*) => {
        {
            use crate::core::logs::LogType;
            use crate::app::AppMode;
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