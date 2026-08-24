//! Central error reporting for the CLI.
//!
//! Every error which reaches the user passes through here. Handlers decide *what* to do with the
//! outcome, not how the error is presented.
//!
//! Most failures leave nothing to carry on with, so they end the program where they happen through
//! [`fail`] / [`OrFail`] rather than threading a status code back up through every layer. [`report`]
//! is reserved for the batch loops, where continuing is genuinely a decision.

use std::{error::Error, fmt::Display, io, process};

use databoxer_core::{
    data::{boxfile::BoxfileError, profiles::ProfileError},
    log,
};

/// Exit code for a command which did all of the work it was asked to
pub const SUCCESS: i32 = 0;
/// Exit code for a command which failed, in whole or in part
pub const FAILURE: i32 = 1;

/// Failures which happen on the CLI's own side of the line, rather than inside the core API
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The supplied `PATH` arguments expanded to nothing worth processing
    #[error("no files to work on")]
    NoInputFiles,
    /// The program was invoked without a subcommand
    #[error("no command was given")]
    NoCommand,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Whether the command should stop after an error, or carry on with the work it has left
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Abort,
    Skip,
}

/// Logs the error, every cause behind it, and any actionable hint
pub fn print(err: &(dyn Error + 'static)) {
    log!(ERROR, "{}", err);

    let mut source = err.source();
    while let Some(cause) = source {
        log!(ERROR, "Caused by: {}", cause);
        source = cause.source();
    }

    hint(err);
}

/// Logs the error and ends the program. For failures which leave nothing to carry on with
pub fn fail(err: &(dyn Error + 'static)) -> ! {
    print(err);
    process::exit(FAILURE)
}

/// Logs the error and reports whether the items left are still worth processing. Only for the batch
/// commands, where a single failure does not have to be the end of the run
pub fn report(err: &(dyn Error + 'static)) -> Verdict {
    print(err);
    fatality(err)
}

/// Suggests a way out of the errors which the user can actually act on
fn hint(err: &(dyn Error + 'static)) {
    if let Some(err) = err.downcast_ref::<ProfileError>() {
        match err {
            ProfileError::AuthenticationFailed =>
                log!(WARN, "Please check your password and try again."),
            ProfileError::NotSelected =>
                log!(WARN, "Please select a profile using 'databoxer profile set <name>' command."),
            _ => {}
        }
    }

    if let Some(BoxfileError::Decryption(_)) = err.downcast_ref::<BoxfileError>() {
        log!(WARN, "The encryption key may be wrong, or the file may have been tampered with.");
    }

    if let Some(CliError::NoCommand) = err.downcast_ref::<CliError>() {
        log!(WARN, "Run 'databoxer --help' to see the available commands.");
    }
}

/// Decides whether an error only affects the item being processed, or the command as a whole
fn fatality(err: &(dyn Error + 'static)) -> Verdict {
    match err.downcast_ref::<BoxfileError>() {
        Some(
            BoxfileError::AlreadyBoxed(_)
            | BoxfileError::NotBoxfile(_)
            | BoxfileError::TooSmall(_)
            | BoxfileError::Io { .. }
        ) => Verdict::Skip,
        _ => Verdict::Abort,
    }
}

/// Unwrap a result, or report the error and quit. For the steps which the rest of the command
/// cannot be attempted without
pub trait OrFail<T> {
    fn or_fail(self) -> T;

    /// As [`OrFail::or_fail`], but prefaces the report with what the program was trying to do
    fn or_fail_with(self, context: impl Display) -> T;
}

impl<T, E: Error + 'static> OrFail<T> for Result<T, E> {
    fn or_fail(self) -> T {
        match self {
            Ok(value) => value,
            Err(err) => fail(&err)
        }
    }

    fn or_fail_with(self, context: impl Display) -> T {
        match self {
            Ok(value) => value,
            Err(err) => {
                log!(ERROR, "{}", context);
                fail(&err)
            }
        }
    }
}
