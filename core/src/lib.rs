//! # Databoxer Core
//!
//! Contains the reusable pieces the program is built from: encryption, the boxfile format, key,
//! profile and authentication management, error types and OS-specific paths. This crate has no
//! knowledge of any particular frontend (CLI, GUI, ...) - it composes nothing on its own and
//! performs no process of its own, leaving that to whichever frontend embeds it. It does own its
//! logging and input prompting, which any frontend can configure.

pub mod data;
pub mod encryption;
pub mod error;
pub mod hex;
pub mod io;
pub mod os;

pub use {
    encryption::cipher::{Checksum, Key, Nonce},
    error::{Error, ErrorType, Result},
};
