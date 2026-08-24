//! Central error reporting for the CLI.
//!
//! Every error which reaches the user passes through `report`, which is the only place that
//! inspects a core error's type. Handlers decide *what* to do with the outcome, not how the error
//! is presented

use databoxer_core::{
    error::{Error, ErrorType, InvalidDataKind, ProfileErrorKind},
    log,
};

/// Exit code used when the CLI itself refuses to start the requested work, rather than a core
/// operation failing. Core failures carry their own, more specific codes
pub const CLI_FAILURE: i32 = 1;

/// Whether the command should stop after an error, or carry on with the work it has left
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Abort,
    Skip,
}

/// How tolerant the running command is of a single failure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Commands which process a list of files, where a bad file can be skipped and the remaining
    /// ones still processed
    Batch,
    /// Commands which perform a single action, leaving nothing to continue with on failure
    Single,
}

/// Logs the error together with its cause and any actionable hint, and reports back whether the
/// caller should stop
pub fn report(err: &Error, policy: Policy) -> Verdict {
    log!(ERROR, "{}", err.message());

    if let Some(cause) = err.cause() {
        log!(ERROR, "Caused by: {}", cause);
    }

    hint(err);
    fatality(err, policy)
}

/// Suggests a way out of the errors which the user can actually act on
fn hint(err: &Error) {
    if let ErrorType::ProfileError(kind) = err.get_type() {
        match kind {
            ProfileErrorKind::AuthenticationFailed =>
                log!(WARN, "Please check your password and try again."),
            ProfileErrorKind::NotSelected =>
                log!(WARN, "Please select a profile using 'databoxer profile set <name>' command."),
            _ => {}
        }
    }
}

/// Decides whether an error only affects the item being processed, or the command as a whole
fn fatality(err: &Error, policy: Policy) -> Verdict {
    if let Policy::Single = policy {
        return Verdict::Abort;
    }

    match err.get_type() {
        // an unsuitable or unreadable file fails only for itself - the rest of the batch is
        // still worth processing
        ErrorType::InvalidData(InvalidDataKind::InvalidFile(_)) => Verdict::Skip,
        ErrorType::IOError(_) => Verdict::Skip,
        _ => Verdict::Abort,
    }
}
