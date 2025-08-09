//! Custom error implementations which are used throughout the whole codebase. Contains a custom
//! result type, error types and their implementations for Display and conversion from other errors.
//! Consult every error's doc for more details

use std::path::PathBuf;
use std::fmt::{self, Display, Formatter};
use crate::log;

/// Custom result type which should be used throughout the codebase for consistency and better
/// error handling
pub type Result<T> = std::result::Result<T, Error>;

/// Custom core error type. It is used to represent different kinds of errors which can occur
/// within the core part of the logic. This error type is used to provide a consistent way of
/// handling errors across the codebase, allowing for better error handling and reporting.
/// 
/// The `Error` type is a wrapper around the `ErrorType` enum, which contains different kinds of
/// errors. Each error type is represented by a variant of the `ErrorType` enum, which can
/// contain additional information about the error, such as a specific kind of error or a cause.
/// 
/// It also contains a cause, which is an optional string that can provide additional context about
/// the source of the error. This allows for more detailed error reporting and can help user to
/// figure out what went wrong.
/// 
/// The `Error` type also provides methods to retrieve the error type, name, message, cause, and
/// exit code. This allows for easy access to the error information and provides a consistent way of
/// handling errors across the codebase.
#[derive(Debug)]
pub struct Error {
    r#type: ErrorType,
    cause: Option<String>,
}

impl Error {
    pub fn new(r#type: ErrorType) -> Self {
        Error { r#type, cause: None }
    }
    
    pub fn with_cause(r#type: ErrorType, cause: impl Display) -> Self {
        Error { r#type, cause: Some(cause.to_string()) }
    }
    
    /// Returns error type. This is the main error type which contains the error kind and additional
    /// information
    pub fn get_type(&self) -> &ErrorType {
        &self.r#type
    }
    
    /// Returns the name of the error type. This is a simple string which only describes the error's
    /// .name
    pub fn name(&self) -> String {
        self.r#type.to_string()
    }
    
    /// Returns the main error message for the error. This is a simple string which describes
    /// the error in a human-readable way. It is usually a short description of the error
    /// and does not contain any cause information.
    pub fn message(&self) -> String {
        match &self.r#type {
            ErrorType::IOError(k) => k.to_string(),
            ErrorType::OSError(k) => k.to_string(),
            ErrorType::InvalidData(k) => k.to_string(),
            ErrorType::CryptoError(k) => k.to_string(),
            ErrorType::ParseError(k) => k.to_string(),
            ErrorType::ProfileError(k) => k.to_string(),
        }
    }
    
    /// Returns the optional cause of the error, if it exists. The cause is a string which can be
    /// any type which implements `Display`. If the cause is not specified, it will return `None`.
    pub fn cause(&self) -> &Option<String> {
        &self.cause
    }
    
    /// Returns an error-specific exit code
    pub fn exit_code(&self) -> i32 {
        // TODO: Implement exit codes for each error type
        1
    }

    /// Default values for whether the error should result in program exiting with an error code
    #[deprecated]
    pub fn should_exit(&self) -> bool {
        true
    }
}

/// Contains different types of errors for each category, both simple errors with a single message 
/// and complex enum errors with different kinds. These custom error types should cover most of the
/// possible program errors which can occur within the core part of the logic.
/// 
/// Each error type is represented by a variant of the `ErrorType` enum, which can contain additional
/// information about the error, like a specific kind of error. 
#[derive(Debug)]
pub enum ErrorType {
    /// Error related to accessing, reading, writing files and anything to do with filesystem.
    IOError(IOErrorKind),
    /// Error related to the user's operating system. Any failed operation which was
    /// based on underlying OS will result in this error. This could be failed retrieval of an
    /// environment variable, unable to access native toolchain or similar
    OSError(OSErrorKind),
    /// Error related to program failing because of it reading some invalid data. Usually the
    /// error cannot be safely handled and/or breaks the core functionality of the program
    InvalidData(InvalidDataKind),
    /// Error related to encryption decryption failure, hashing and everything else to do
    /// with the encryption process
    CryptoError(CryptoErrorKind),
    /// Error related to serializing and deserializing. Failed parsing of profile and config files
    /// along with any other process related to data serialization results in this error
    ParseError(ParseErrorKind),
    /// Error related to anything to do with user's profile. This could mean profile not
    /// being found, no profile being currently selected or any other kind
    ProfileError(ProfileErrorKind),
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ErrorType::IOError(_) => write!(f, "IO Error"),
            ErrorType::OSError(_) => write!(f, "OS Error"),
            ErrorType::InvalidData(_) => write!(f, "Invalid Data Error"),
            ErrorType::CryptoError(_) => write!(f, "Cryptography Error"),
            ErrorType::ParseError(_) => write!(f, "Parsing Error"),
            ErrorType::ProfileError(_) => write!(f, "User Profile Error"),
        }
    }
}

#[derive(Debug)]
pub enum IOErrorKind {
    /// Unable to write to the file
    Write(PathBuf),
    /// Unable to read the file
    Read(PathBuf),
    /// Unable to create a new file or directory
    Create(PathBuf),
    /// Unable to delete the file or directory
    Delete(PathBuf),
    /// The file or directory was not found
    NotFound(PathBuf),
    /// Unable to read from or write to standard IO, such as stdin, stdout or stderr
    StandardIO,
    /// Standard IO error, which is automatically converted from `std::io::Error`
    Misc,
}

impl Display for IOErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            IOErrorKind::Write(path) => write!(f, "Unable to write to '{}'", path.display()),
            IOErrorKind::Read(path) => write!(f, "Unable to read '{}'", path.display()),
            IOErrorKind::Create(path) => write!(f, "Unable to create a new file/directory at '{}'", path.display()),
            IOErrorKind::Delete(path) => write!(f, "Unable to delete file/directory at '{}'", path.display()),
            IOErrorKind::NotFound(path) => write!(f, "File/directory '{}' not found", path.display()),
            IOErrorKind::StandardIO => write!(f, "Unable to read from or write to standard IO (console)"),
            IOErrorKind::Misc => write!(f, "An IO error has occurred"),
        }
    }
}

#[derive(Debug)]
pub enum OSErrorKind {
    EnvVariable(String),
}

impl Display for OSErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OSErrorKind::EnvVariable(s) => write!(f, "Unable to get the '{}' environment variable", s),
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
    /// The provided file is invalid. This could mean that the file was
    /// already encrypted, decrypted or anything else which would mark it
    /// invalid in a given context. 
    InvalidFile(PathBuf),
}

impl Display for InvalidDataKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InvalidDataKind::InvalidHex(s) => write!(f, "Invalid hex: {}", s),
            InvalidDataKind::InvalidLength(s) => write!(f, "Invalid length of '{}'", s),
            InvalidDataKind::MissingData(s) => write!(f, "Data of '{}' is missing", s),
            InvalidDataKind::InvalidFile(p) => write!(f, "Invalid file '{}' provided", p.display()),
        }
    }
}

#[derive(Debug)]
pub enum CryptoErrorKind {
    Encryption,
    Decryption,
    Hash(String),
}

impl Display for CryptoErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CryptoErrorKind::Encryption=> write!(f, "Unable to encrypt data"),
            CryptoErrorKind::Decryption => write!(f, "Unable to decrypt data"),
            CryptoErrorKind::Hash(s) => write!(f, "Unable to generate a hash for '{}'", s),
        }
    }
}

#[derive(Debug)]
pub enum ParseErrorKind {
    Encoding(String),
    Decoding(String),
    JSON(PathBuf, usize, usize),
    TOML(PathBuf),
    Boxfile(PathBuf),
}

impl Display for ParseErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ParseErrorKind::Encoding(s) => write!(f, "Unable to encode data of '{}'", s),
            ParseErrorKind::Decoding(s) => write!(f, "Unable to decode data of '{}'", s),
            ParseErrorKind::JSON(path, line, column) => write!(f, "Unable to parse JSON file '{}' at ({}, {})", path.display(), line, column),
            ParseErrorKind::TOML(p) => write!(f, "Unable to parse TOML file '{}'", p.display()),
            ParseErrorKind::Boxfile(p) => write!(f, "Unable to parse Boxfile '{}'", p.display()),
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
            ProfileErrorKind::AuthenticationFailed => write!(f, "Authentication failed"),
            ProfileErrorKind::MismatchedProfile => write!(f, "Mismatched profile"),
        }
    }
}

/// General error printer which outputs the error itself and detailed information if needed
#[deprecated]
pub fn print_error(err: &Error) {
    use crate::log;
    
    log!(ERROR, "{}", err.name());
    log!(ERROR, "{}", err.message());
    if let Some(cause) = err.cause() {
        log!(ERROR, "Cause: {}", cause);
    }
}

/// Macro used as a shortcut for creating a new Databoxer Core Error. The macro will automatically 
/// import the necessary error types and create a new error instance.
/// 
/// A new error is generated by providing the error *type* (`Error::SomeError`) and an error *kind*
/// (`SomeErrorKind::SomeKind`) after the colon: `new_err!(SomeError: SomeKind)`. 
/// 
/// If the error kind has a **value**, it should be specified after the kind, separated by a comma:
/// `new_err!(SomeError: Kind, val)`. **Multiple kind values** can be provided as well, separated 
/// by commas: `new_err!(SomeError: Kind, val1, val2, val3, ...)`.
/// 
/// If the error kind has a **cause**, it should be specified after the kind, separated by a semicolon:
/// `new_err!(SomeError: Kind; cause)`. Only one cause can be provided.
/// 
/// If the error kind has a **value** and a **cause**, they should be specified after the kind, 
/// separated by a comma and a semicolon: `new_err!(SomeError: Kind, val; cause)`. **Multiple kind 
/// values** can be provided as well, separated by commas: `new_err!(SomeError: Kind, val1, 
/// val2, val3, ...; cause)`.
#[macro_export]
macro_rules! new_err {
    ($err:ident: $kind:ident) => {
        {
            use paste::paste;
            paste! {
                use crate::core::error::{Error, ErrorType, [<$err Kind>]};
                Error::new(ErrorType::$err([<$err Kind>]::$kind))
            }
        }
    };
    ($err:ident: $kind:ident, $($val:expr),*) => {
        {
            use paste::paste;
            paste! {
                use crate::core::error::{Error, ErrorType, [<$err Kind>]};
                Error::new(ErrorType::$err([<$err Kind>]::$kind($($val),*)))
            }
        }
    };
    ($err:ident: $kind:ident; $cause:expr) => {
        {
            use paste::paste;
            paste! {
                use crate::core::error::{Error, ErrorType, [<$err Kind>]};
                Error::with_cause(ErrorType::$err([<$err Kind>]::$kind), $cause)
            }
        }
    };
    ($err:ident: $kind:ident, $($val:expr),*; $cause:expr) => {
        {
            use paste::paste;
            paste! {
                use crate::core::error::{Error, ErrorType, [<$err Kind>]};
                Error::with_cause(ErrorType::$err([<$err Kind>]::$kind($($val),*)), $cause)
            }
        }
    };
}

/// Macro used as a shortcut for comparing errors by their *type* and *kind*. 
///
/// Comparison can be done in two ways:
/// - by error *type* only (e.g. `err_cmp!(err, SomeError)`)
/// - by error *type* and *kind* (e.g. `err_cmp!(err, SomeError, Kind)`)
/// Where `SomeError` is `Error::SomeError` and `Kind` is `SomeErrorKind::Kind`.
/// 
/// If the error *kind* has a value, `()` should be added at the end of the *kind* specification
/// (e.g. `err_cmp!(err, SomeError, Kind())`)
#[macro_export]
macro_rules! err_cmp {
    ($err:expr, $err_type:ident) => {
        {
            use crate::core::error::ErrorType;
            if let ErrorType::$err_type(_) = &$err.get_type() {
                true
            } else {
                false
            }
        }
    };
    ($err:expr, $err_type:ident, $err_kind:ident) => {
        {
            use paste::paste;
            use crate::core::error::ErrorType;
            if let ErrorType::$err_type(kind) = &$err.get_type() {
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
            use crate::core::error::ErrorType;
            if let ErrorType::$err_type(kind) = &$err.get_type() {
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
#[deprecated]
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
    ($err:expr; $($err_type:ident),*) => {
        use crate::core::error::{ErrorType, print_error};
        print_error(&$err);
        match $err.get_type() {
            $(
                ErrorType::$err_type(_) => std::process::exit($err.exit_code());
            ),*
            _ => {}
        }
    };
    ($err:expr; $($err_type:ident $should:expr);*) => {
        use crate::core::error::{ErrorType, print_error};
        print_error(&$err);
        match $err.get_type() {
            $(
                ErrorType::$err_type(_) => {
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
        let err = Error::new(ErrorType::ProfileError(ProfileErrorKind::AuthenticationFailed));
        
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
        
        let str_err = new_err!(InvalidData: InvalidHex, "placeholder".to_string());
        assert!(err_cmp!(str_err, InvalidData, InvalidHex()));
    }
}
