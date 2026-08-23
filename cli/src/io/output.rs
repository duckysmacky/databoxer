//! CLI-only helper for printing status/outcome messages (to `stderr`, mirroring the logger's
//! stream) and program output data (to `stdout`). Distinct from `databoxer_core::io::log`,
//! which is for diagnostic messages only

use std::fmt;

enum PrintType {
    Status,
    Success,
    Fail,
}

impl PrintType {
    fn icon(&self) -> &'static str {
        match self {
            PrintType::Status => "*",
            PrintType::Success => "+",
            PrintType::Fail => "x",
        }
    }
}

pub fn status(args: fmt::Arguments) {
    eprintln!("[{}] {}", PrintType::Status.icon(), args);
}

pub fn success(args: fmt::Arguments) {
    eprintln!("[{}] {}", PrintType::Success.icon(), args);
}

pub fn fail(args: fmt::Arguments) {
    eprintln!("[{}] {}", PrintType::Fail.icon(), args);
}

pub fn data(args: fmt::Arguments) {
    println!("{}", args);
}

#[macro_export]
macro_rules! output {
    (STATUS, $($arg:tt)*) => { $crate::io::output::status(format_args!($($arg)*)) };
    (SUCCESS, $($arg:tt)*) => { $crate::io::output::success(format_args!($($arg)*)) };
    (FAIL, $($arg:tt)*) => { $crate::io::output::fail(format_args!($($arg)*)) };
    (DATA, $($arg:tt)*) => { $crate::io::output::data(format_args!($($arg)*)) };
}
