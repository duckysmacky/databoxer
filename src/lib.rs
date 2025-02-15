//! # Databoxer API
//!
//! This library functions like an API between the CLI and GUI wrappers and the rest of the core
//! program code. It contains all the main functions related to the Databoxer's functionality, like
//! encryption, decryption, key and profile management.

pub use core::error::{Error, Result};
pub use core::options;
pub use core::encryption::{boxfile::Boxfile, cipher::{Checksum, Key, Nonce}};
use core::{key, profile};

pub mod app;
pub mod cli;
mod core;

/// Encrypts the file at the given path. Extra options can be provided to control the process.
///
/// Most errors can be safely handled without an unsuccessful exit (e.g. file can just be skipped).
/// Although it is better to exit on errors related with user authentication and profiles, as the
/// program will simply not work without a user profile
pub fn encrypt(file_path: &std::path::Path, options: &mut options::EncryptionOptions) -> Result<()> {
    core::encrypt(file_path, &options.password, options.keep_original_name, &mut options.output_paths)
}

/// Decrypts the file at the given path. Extra options can be provided to control the process.
/// Works similarly to the `encrypt` function just the other way around.
///
/// Most errors can be safely handled without an unsuccessful exit (e.g. file can just be skipped).
/// Although it is better to exit on errors related with user authentication and profiles, as the
/// program will simply not work without a user profile
pub fn decrypt(file_path: &std::path::Path, options: &mut options::DecryptionOptions) -> Result<()> {
    core::decrypt(file_path, &options.password, &mut options.output_paths)
}


/// Parses the provided boxfile and retrieves original metadata from the header.
/// 
/// Returns a vector which contains strings with retrieved information about original file name,
/// extension, create, modify and access time. Will skip the unknown metadata unless optionally 
/// specified not to
pub fn information(file_path: &std::path::Path, options: options::InformationOptions) -> Result<Vec<String>> {
    core::get_information(file_path, options.show_unknown)
}

/// Creates a new profile with the provided password and profile name. Will **not** automatically
/// switch to the new profile
pub fn create_profile(profile_name: &str, options: options::ProfileCreateOptions) -> Result<()> {
    profile::create(profile_name, &options.password)
}

/// Deletes the profile with the corresponding name. After deletion will switch back to the first
/// profile in the list or if there are no profiles left set the current profile to `None`
///
/// Needs the target profile's password to authenticate
pub fn delete_profile(profile_name: &str, options: options::ProfileDeleteOptions) -> Result<()> {
    profile::delete(profile_name, &options.password)
}

/// Select (set as the current) the profile with the corresponding name
///
/// Needs the target profile's password to authenticate
pub fn select_profile(profile_name: &str, options: options::ProfileSelectOptions) -> Result<()> {
    profile::select(profile_name, &options.password)
}

/// Returns the name of the currently selected profile
///
/// No authentication needed, as it just returns the name
pub fn get_profile() -> Result<String> {
    profile::get_current()
}

/// Returns the names of all currently available profiles
///
/// No authentication needed, as it just returns the names
pub fn get_profiles() -> Result<Vec<String>> {
    profile::get_all()
}

/// Generates a new encryption key for the current profile
///
/// **Warning:** this will replace the current encryption key, meaning that currently encrypted
/// files will no longer be able to be decrypted due to a different key being used
///
/// Needs the current profile's password to authenticate
pub fn new_key(options: options::KeyNewOptions) -> Result<()> {
    key::new(&options.password)
}

/// Returns the encryption key being used by the current profile in a hex format
///
/// Needs the current profile's password to authenticate
pub fn get_key(options: options::KeyGetOptions) -> Result<String> {
    key::get(&options.password, options.as_byte_array)
}

/// Sets a new encryption key for the current profile. The input key has to be a valid 32-byte long
/// hex key for it to work (e.g. input key of `"0128AE1005..."` translates to `[1, 40, 174, 16, 5,
/// ...]`)
///
/// Needs the current profile's password to authenticate
pub fn set_key(new_key: &str, options: options::KeySetOptions) -> Result<()> {
    key::set(new_key, &options.password)
}