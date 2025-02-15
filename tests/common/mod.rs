//! Contains common functions and constants for running tests.

use std::{fs, io};
use std::path::Path;
use databoxer::Error;
use databoxer::options;

pub mod command;

pub const PROFILE_NAME: &str = "common-test-profile";
pub const PASSWORD: &str = "common-test-password";
pub const ORIGINAL_DIR: &str = "files/original";
pub const TEST_DIR: &str = "files/test";

/// Global test environment setup (must be run before each test)
pub fn setup() {
    let password = String::from(PASSWORD);
    let mut create_options = options::ProfileCreateOptions::default();
    create_options.password = Some(&password);
    
    let mut select_options = options::ProfileSelectOptions::default();
    select_options.password = Some(&password);
    
    databoxer::create_profile(PROFILE_NAME, create_options)
        .unwrap_or_else(|err| match err {
            Error::ProfileError(_) => println!("{}", err),
            _ => panic!("Unable to create test profile: {}", err)
        });

    databoxer::select_profile(PROFILE_NAME, select_options)
        .unwrap_or_else(|err| match err {
            Error::ProfileError(_) => println!("{}", err),
            _ => panic!("Unable to select test profile: {}", err)
        });

    copy_original_files()
        .unwrap_or_else(|err| panic!("Unable to copy original test files: {}", err));
}

/// Global test environment cleanup (must be run after each test)
pub fn cleanup() {
    let password = String::from(PASSWORD);
    let mut delete_options = options::ProfileDeleteOptions::default();
    delete_options.password = Some(&password);
    
    databoxer::delete_profile(PROFILE_NAME, delete_options)
        .unwrap_or_else(|err| match err {
            Error::ProfileError(_) => println!("{}", err),
            _ => panic!("Unable to delete test profile: {}", err)
        });

    delete_test_files()
        .unwrap_or_else(|err| panic!("Unable to delete test files: {}", err));
}

/// Copies original test files for use in tests
fn copy_original_files() -> io::Result<()> {
    let test_dir = Path::new(TEST_DIR);

    if !test_dir.exists() {
        fs::create_dir(test_dir)?;
    }

    for entry in fs::read_dir(ORIGINAL_DIR)? {
        let original_file = entry?.path();

        if original_file.is_file() {
            let file_name = original_file.file_name().unwrap();
            let test_file = test_dir.join(file_name);

            fs::copy(&original_file, &test_file)?;
        }
    }

    Ok(())
}

/// Deletes and cleans up test files
fn delete_test_files() -> io::Result<()> {
    let test_dir = Path::new(TEST_DIR);

    if test_dir.exists() {
        fs::remove_dir_all(test_dir)?;
    }

    Ok(())
}