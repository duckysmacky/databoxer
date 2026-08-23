use std::fmt;
use std::sync::OnceLock;

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
    pub fn icon(&self) -> &'static str {
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

/// Implemented by whichever frontend embeds this crate (CLI, GUI, ...) to receive log/output
/// messages
pub trait LogSink: Send + Sync {
    fn log(&self, log_type: LogType, message: fmt::Arguments);
    fn output(&self, list: bool, data: fmt::Arguments);
}

pub static LOG_SINK: OnceLock<Box<dyn LogSink>> = OnceLock::new();

/// Registers the log sink used by `log!`/`output!`. Should be called once during startup
pub fn set_log_sink(sink: Box<dyn LogSink>) {
    LOG_SINK.set(sink).ok();
}

/// Macro used for logging messages throughout the program. Dispatches to the registered
/// `LogSink`, or does nothing if none has been registered yet
#[macro_export]
macro_rules! log {
    ($log_type:ident, $($arg:tt)*) => {{
        use $crate::io::log::{self, LogType};
        if let Some(sink) = log::LOG_SINK.get() {
            sink.log(LogType::$log_type, format_args!($($arg)*));
        }}
    };
}

/// Macro used for better data output. Acts like a wrapper above print! in order to produce a
/// more suitable output based on the log sink's mode (cleaner and simpler output when in quiet
/// mode). Add the `list` keyword to suggest that the data provided should be outputted as a list
#[macro_export]
macro_rules! output {
    (list $($args:tt)*) => {
        if let Some(sink) = $crate::io::log::LOG_SINK.get() {
            sink.output(true, format_args!($($args)*));
        }
    };
    ($($args:tt)*) => {
        if let Some(sink) = $crate::io::log::LOG_SINK.get() {
            sink.output(false, format_args!($($args)*));
        }
    };
}
