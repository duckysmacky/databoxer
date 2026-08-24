#[path = "common/command.rs"]
pub mod command;

use std::{path::Path, fs, io};

use databoxer_core::{
    data::{self, profiles::Profile},
    ErrorType,
};

pub const PROFILE_NAME: &str = "common-test-profile";
pub const PASSWORD: &str = "common-test-password";
pub const ORIGINAL_DIR: &str = "tests/files/original";
pub const TEST_DIR: &str = "tests/files/test";

/// Global test environment setup (must be run before each test)
pub fn setup() {
    let mut profiles = data::get_profiles()
        .unwrap_or_else(|err| panic!("Unable to get profiles: {}", err.message()));

    let profile = Profile::new(PROFILE_NAME, PASSWORD)
        .unwrap_or_else(|err| panic!("Unable to build test profile: {}", err.message()));

    profiles.new_profile(profile)
        .unwrap_or_else(|err| match err.get_type() {
            ErrorType::ProfileError(_) => println!("{}", err.message()),
            _ => panic!("Unable to create test profile: {}", err.message())
        });

    profiles.set_current(PASSWORD, PROFILE_NAME)
        .unwrap_or_else(|err| match err.get_type() {
            ErrorType::ProfileError(_) => println!("{}", err.message()),
            _ => panic!("Unable to select test profile: {}", err.message())
        });

    copy_original_files()
        .unwrap_or_else(|err| panic!("Unable to copy original test files: {}", err));
}

/// Global test environment cleanup (must be run after each test)
pub fn cleanup() {
    let mut profiles = data::get_profiles()
        .unwrap_or_else(|err| panic!("Unable to get profiles: {}", err.message()));

    profiles.delete_profile(PASSWORD, PROFILE_NAME)
        .unwrap_or_else(|err| match err.get_type() {
            ErrorType::ProfileError(_) => println!("{}", err.message()),
            _ => panic!("Unable to delete test profile: {}", err.message())
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
