//! Custom error implementations which are used throughout the whole codebase. Contains a custom
//! result type, error types and their implementations for Display and conversion from other errors.
//! Consult every error's doc for more details
#![allow(irrefutable_let_patterns)]

use std::path::PathBuf;
use std::{fmt, io};
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use crate::log;

/// Custom result type which should be used throughout the codebase for consistency and better
/// error handling
pub type Result<T> = std::result::Result<T, Error>;

/// Custom Databoxer error type. Contains different kinds of errors for each category, both simple
/// errors with a single message and complex enum errors with different kinds. These custom error
/// types should cover most of the possible program errors
///
/// Not every error is process-ending, but instead can just be handled as a warning or a
/// notification for the user
#[repr(i32)]
#[derive(Debug)]
pub enum Error {
    /// Error related to accessing, reading, writing files and anything to do with filesystem.
    IOError(IOErrorKind),
    /// Error related to the user's operating system. Any failed operation which was
    /// based on underlying OS will result in this error. This could be failed retrieval of an
    /// environment variable, unable to access native toolchain or similar
    OSError(OSErrorKind),
    /// Error related to program failing because of it reaching some invalid data. Usually the
    /// error cannot be safely handled and/or breaks the core functionality of the program
    InvalidData(InvalidDataKind),
    /// Error related to incorrect data being provided to the program. This usually means an error
    /// on the user's side, like wrong type of the file being attempted to encrypt. Don't mistake
    /// with `InvalidData`, as this error is produced by the user directly
    InvalidInput(InvalidInputKind),
    /// Error related to encryption decryption failure, hashing and everything else to do
    /// with the encryption process
    EncryptionError(EncryptionErrorKind),
    /// Error related to serializing and deserializing. Failed parsing of profile and config files
    /// along with any other process related to data serialization results in this error
    SerializeError(SerializeErrorKind),
    /// Error related to anything to do with user's profile. This could mean profile not
    /// being found, no profile being currently selected or any other kind
    ProfileError(ProfileErrorKind),
    /// Error related to program's configuration
    ConfigError(ConfigErrorKind),
}

impl Error {
    /// Default values for whether the error should result in program exiting with an error code
    pub fn should_exit(&self) -> bool {
        match self {
            Error::IOError(_) => true,
            Error::OSError(_) => true,
            Error::InvalidData(_) => true,
            Error::InvalidInput(_) => true,
            Error::EncryptionError(_) => true,
            Error::SerializeError(_) => true,
            Error::ProfileError(_) => true,
            Error::ConfigError(_) => true,
        }
    }
    
    /// Returns an error-specific exit code
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::IOError(_) => 1,
            Error::OSError(_) => 2,
            Error::InvalidData(_) => 3,
            Error::InvalidInput(_) => 4,
            Error::EncryptionError(_) => 5,
            Error::SerializeError(_) => 6,
            Error::ProfileError(_) => 7,
            Error::ConfigError(_) => 8,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::IOError(e) => write!(f, "IO error: {}", e),
            Error::OSError(e) => write!(f, "OS error: {}", e),
            Error::InvalidData(e) => write!(f, "Invalid data: {}", e),
            Error::InvalidInput(e) => write!(f, "Invalid input provided: {}", e),
            Error::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            Error::SerializeError(e) => write!(f, "{}", e),
            Error::ProfileError(e) => write!(f, "Profile error: {}", e),
            Error::ConfigError(e) => write!(f, "Configuration error: {}", e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(IOErrorKind::StdError(
            IOErrorContainer {
                kind: err.kind(),
                message: err.to_string(),
            }
        ))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerializeError(SerializeErrorKind::JSONParseError(err.to_string(), err.line(), err.column()))
    }
}

impl From<toml::ser::Error> for Error {
    fn from(err: toml::ser::Error) -> Self {
        Error::SerializeError(SerializeErrorKind::TOMLParseError(err.to_string()))
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Error::SerializeError(SerializeErrorKind::TOMLParseError(err.to_string()))
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(err: bincode::error::EncodeError) -> Self {
        Error::SerializeError(SerializeErrorKind::EncodingError(err.to_string()))
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(err: bincode::error::DecodeError) -> Self {
        Error::SerializeError(SerializeErrorKind::DecodingError(err.to_string()))
    }
}

#[derive(Debug)]
pub enum IOErrorKind {
    /// The std IO error (std::io::Error)
    StdError(IOErrorContainer),
    /// The provided file was not found
    NotFound(PathBuf),
    /// The provided file is not supported for operations
    NotSupported(PathBuf),
}

impl Display for IOErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IOErrorKind::StdError(e) => write!(f, "{} - {}", e.kind, e.message),
            IOErrorKind::NotFound(p) => write!(f, "File '{}' not found", p.display()),
            IOErrorKind::NotSupported(p) => write!(f, "File '{}' is not supported", p.display()),
        }
    }
}

#[derive(Debug)]
/// Works like a wrapper above the std::Error. Automatically converted from it
pub struct IOErrorContainer {
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug)]
pub enum OSErrorKind {
    EnvVariableUnavailable(String),
}

impl Display for OSErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OSErrorKind::EnvVariableUnavailable(s) => write!(f, "Unable to get the '{}' environment variable", s),
        }
    }
}

#[derive(Debug)]
pub enum InvalidDataKind {
    /// The provided hex is invalid in some form. This could be its length,
    /// incorrect bytes or anything else related to hex
    InvalidHex(String),
    /// The length of *x* type is invalid
    InvalidLength(String),
    /// Crucial data is missing, meaning the process cannot continue
    MissingData(String),
}

impl Display for InvalidDataKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InvalidDataKind::InvalidHex(s) => write!(f, "Invalid hex number ({})", s),
            InvalidDataKind::InvalidLength(s) => write!(f, "Invalid length of {}", s),
            InvalidDataKind::MissingData(s) => write!(f, "Some data is missing ({})", s),
        }
    }
}

#[derive(Debug)]
pub enum InvalidInputKind {
    /// The provided file is invalid. This could mean that the file was
    /// already encrypted, decrypted or anything else which would mark it
    /// invalid in a given context. 
    InvalidFile(String),
}

impl Display for InvalidInputKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InvalidInputKind::InvalidFile(s) => write!(f, "Invalid file provided ({})", s),
        }
    }
}

#[derive(Debug)]
pub enum EncryptionErrorKind {
    CipherError(String),
    HashError(String),
}

impl Display for EncryptionErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionErrorKind::CipherError(s) => write!(f, "Unable to apply cipher ({})", s),
            EncryptionErrorKind::HashError(s) => write!(f, "Unable to generate a hash ({})", s),
        }
    }
}

#[derive(Debug)]
pub enum SerializeErrorKind {
    JSONParseError(String, usize, usize),
    TOMLParseError(String),
    BoxfileParseError(String),
    EncodingError(String),
    DecodingError(String),
}

impl Display for SerializeErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SerializeErrorKind::JSONParseError(s, line, column) => write!(f, "Error parsing JSON file ({}, {}): {}", line, column, s),
            SerializeErrorKind::TOMLParseError(s) => write!(f, "Error parsing TOML file: {}", s),
            SerializeErrorKind::BoxfileParseError(s) => write!(f, "Error parsing boxfile: {}", s),
            SerializeErrorKind::EncodingError(s) => write!(f, "Unable to encode data: {}", s),
            SerializeErrorKind::DecodingError(s) => write!(f, "Unable to decode data: {}", s),
        }
    }
}

#[derive(Debug)]
pub enum ProfileErrorKind {
    NotFound(String),
    NotSelected,
    AlreadySelected(String),
    AlreadyExists(String),
    AuthenticationFailed,
    MismatchedProfile,
}

impl Display for ProfileErrorKind {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ProfileErrorKind::NotFound(s) => write!(f, "Profile '{}' not found", s),
            ProfileErrorKind::NotSelected => write!(f, "No profile is currently selected"),
            ProfileErrorKind::AlreadySelected(s) => write!(f, "Profile '{}' is already selected", s),
            ProfileErrorKind::AlreadyExists(s) => write!(f, "Profile '{}' already exists", s),
            ProfileErrorKind::AuthenticationFailed => write!(f, "Authentication failed. Invalid profile password provided"),
            ProfileErrorKind::MismatchedProfile => write!(f, "Mismatched profile. File seems to be encrypted with a different one."),
        }
    }
}

#[derive(Debug)]
pub enum ConfigErrorKind {}

impl Display for ConfigErrorKind {
    fn fmt(&self, _f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

/// General error printer which outputs the error itself and detailed information if needed
pub fn print_error(err: &Error) {
    log!(ERROR, "{}", err);
    match &err {
        Error::ProfileError(kind) => {
            if let ProfileErrorKind::AuthenticationFailed = kind {
                log!(WARN, "Try again or use a different profile")
            } else {
                log!(WARN, "New profile can be created with 'databoxer profile new'");
            }
        },
        Error::ConfigError(_) => {
            log!(WARN, "Please check the config file for any mistakes and try again");
        }
        Error::EncryptionError(kind) => {
            if let EncryptionErrorKind::CipherError(_) = kind {
                log!(WARN, "Please check if the correct profile is used");
            }
        }
        _ => {}
    }
}

/// Macro used as a shortcut for creating a new Databoxer Error.
/// 
/// A new error is generated by providing the error *type* (`SomeError`) and an error *kind*
/// (`SomeErrorKind`) after the colon: `new_err!(ProfileError, NotSelected)`. 
/// 
/// An error message should also be supplied if the error *kind* requires one:
/// `new_err!(ProfileError, NotFound, "message")`. Automatically converts to needed message
/// type if possible
#[macro_export]
macro_rules! new_err {
    ($err:ident: $kind:ident) => {
        {
            use paste::paste;
            paste! {
                use crate::core::error::{Error, [<$err Kind>]};
                Error::$err([<$err Kind>]::$kind)
            }
        }
    };
    ($err:ident: $kind:ident, $msg:expr) => {
        {
            use paste::paste;
            paste! {
                use crate::core::error::{Error, [<$err Kind>]};
                Error::$err([<$err Kind>]::$kind($msg.to_string()))
            }
        }
    };
}

/// Macro used as a shortcut for comparing errors by their *type* and *kind*. 
/// 
/// Comparison can be done in two ways:
/// - by *type* only (e.g. `err_cmp!(err, ProfileError)`)
/// - by *type* and *kind* (e.g. `err_cmp!(err, ProfileError, NotSelected)`)
/// 
/// If the error *kind* has a value, `()` should be added at the end of the *kind* specification
/// (e.g. `err_cmp!(err, ProfileError, NotFound())`)
#[macro_export]
macro_rules! err_cmp {
    ($err:expr, $err_type:ident) => {
        {
            use crate::core::error::Error;
            if let Error::$err_type(_) = &$err {
                true
            } else {
                false
            }
        }
    };
    ($err:expr, $err_type:ident, $err_kind:ident) => {
        {
            use paste::paste;
            use crate::core::error::Error;
            if let Error::$err_type(kind) = &$err {
                paste! {
                    use crate::core::error::[<$err_type Kind>];
                    if let [<$err_type Kind>]::$err_kind = kind {
                        true
                    } else {
                        false
                    }
                }
            } else {
                false
            }
        }
    };
    ($err:expr, $err_type:ident, $err_kind:ident()) => {
        {
            use paste::paste;
            use crate::core::error::Error;
            if let Error::$err_type(kind) = &$err {
                paste! {
                    use crate::core::error::[<$err_type Kind>];
                    if let [<$err_type Kind>]::$err_kind(_) = kind {
                        true
                    } else {
                        false
                    }
                }
            } else {
                false
            }
        }
    };
}

/// Macro to specify on which error kind the program will exit with an error code. Additionally,
/// calls `error::print_error()` to log error and provide detailed information if needed
/// 
/// - Error kinds separated with a comma will be marked as exit-resulting: `exits_on!(err, OSError,
/// ProfileError)`
/// - If the error kinds are seperated with a semicolon, weather they should result in an exit will
/// be decided by the boolean expression for the kind, else will decide depending on the default
/// value: `exits_on!(err; IOError true; ProfileError false)`
/// - `default` keyword will specify to exit on the error based on the default value:
/// `exits_on!(err; default)`
/// - `all` keyword will specify to exit no matter which error kind it is: `exits_on!(err; all)`
#[macro_export]
macro_rules! exits_on {
    ($err:expr; default) => {
        use crate::core::error::print_error;
        print_error(&$err);
        if $err.should_exit() {
            std::process::exit($err.exit_code());
        }
    };
    ($err:expr; all) => {
        use crate::core::error::print_error;
        print_error(&$err);
        std::process::exit($err.exit_code());
    };
    ($err:expr; $($err_kind:ident),*) => {
        use crate::core::error::{Error, print_error};
        print_error(&$err);
        match $err {
            $(
                Error::$err_kind(_) => std::process::exit($err.exit_code());
            ),*
            _ => {}
        }
    };
    ($err:expr; $($err_kind:ident $should:expr);*) => {
        use crate::core::error::{Error, print_error};
        print_error(&$err);
        match $err {
            $(
                Error::$err_kind(_) => {
                    if $should {
                        std::process::exit($err.exit_code());
                    }
                }
            ),*
            _ => {
                if $err.should_exit() {
                    std::process::exit($err.exit_code());
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_err_cmp() {
        let err = Error::ProfileError(ProfileErrorKind::AuthenticationFailed);
        
        let compare_type = err_cmp!(err, ProfileError);
        assert!(compare_type);
        
        let compare_kind = err_cmp!(err, ProfileError, AuthenticationFailed);
        assert!(compare_kind);
        
        let failed_compare_type = err_cmp!(err, OSError);
        assert_ne!(failed_compare_type, true);
        
        let failed_compare_kind = err_cmp!(err, ProfileError, MismatchedProfile);
        assert_ne!(failed_compare_kind, true);
    }
    
    #[test]
    fn test_new_err_macro() {
        let err = new_err!(ProfileError: NotSelected);
        assert!(err_cmp!(err, ProfileError, NotSelected));
        
        let str_err = new_err!(InvalidData: InvalidHex, "placeholder");
        assert!(err_cmp!(str_err, InvalidData, InvalidHex()));
    }
}
