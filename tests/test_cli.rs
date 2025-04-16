//! Tests to test how the CLI client performs with different flags and inputs

use std::fs::File;
use std::io::Write;
use std::iter;
use std::path::Path;
use rand::Rng;

mod common;

/// Local test environment setup
fn setup() {
    common::cleanup();
    common::setup();
}

/// Local test environment cleanup
fn cleanup() {
    common::cleanup();
}

/// Generate a random 64-byte HEX string (a new key)
fn generate_key() -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEF";
    let mut rng = rand::rng();
    iter::repeat_with(|| CHARSET[rng.random_range(0..16)] as char)
        .take(64)
        .collect::<String>()
}

/// Macro for fast Databoxer executable command generation and execution. Will initiate a new command
/// with provided arguments, execute it and print its output, returning the resulting `Output`
macro_rules! databoxer_cmd {
    ($cmd:expr) => {
        {
            use common::command::{DataboxerCommand, print_output};
            let command = DataboxerCommand::new($cmd, false);
            let output = command.execute();
            print_output(&output);
            output
        }
    };
    ($cmd:expr; $($args:expr),+) => {
        {
            use common::command::{DataboxerCommand, print_output};
            let mut command = DataboxerCommand::new($cmd, false);
            for arg in [$($args),*] {
                command.arg(arg);
            }
            let output = command.execute();
            print_output(&output);
            output
        }
    };
    (p $cmd:expr) => {
        {
            use common::command::{DataboxerCommand, print_output};
            let command = DataboxerCommand::new($cmd, true);
            let output = command.execute();
            print_output(&output);
            output
        }
    };
    (p $cmd:expr; $($args:expr),+) => {
        {
            use common::command::{DataboxerCommand, print_output};
            let mut command = DataboxerCommand::new($cmd, true);
            for arg in [$($args),*] {
                command.arg(arg);
            }
            let output = command.execute();
            print_output(&output);
            output
        }
    };
}

#[test]
fn test_text_encryption() {
    setup();

    let test_dir = Path::new(common::TEST_DIR);
    let test_file = test_dir.join("text.txt");

    let output = databoxer_cmd!(p "box"; &test_file);
    assert!(output.status.success(), "Text encryption failed");

    let output = databoxer_cmd!(p "unbox"; &test_file);
    assert!(output.status.success(), "Text decryption failed");

    cleanup();
}

#[test]
fn test_image_encryption() {
    setup();

    let test_dir = Path::new(common::TEST_DIR);
    let test_file = test_dir.join("image.png");

    let output = databoxer_cmd!(p "box"; &test_file);
    assert!(output.status.success(), "Image encryption failed");

    let output = databoxer_cmd!(p "unbox"; &test_file);
    assert!(output.status.success(), "Image decryption failed");

    cleanup();
}

#[test]
fn test_directory_encryption() {
    setup();

    let test_dir = Path::new(common::TEST_DIR);

    let output = databoxer_cmd!(p "box"; &test_dir);
    assert!(output.status.success(), "Directory encryption failed");

    let output = databoxer_cmd!(p "unbox"; &test_dir);
    assert!(output.status.success(), "Directory decryption failed");

    cleanup();
}

#[test]
fn test_recursive_encryption() {
    setup();

    let test_dir = Path::new(common::TEST_DIR);

    let output = databoxer_cmd!(p "box"; &test_dir);
    assert!(output.status.success(), "Recursive encryption failed");

    let output = databoxer_cmd!(p "unbox"; &test_dir);
    assert!(output.status.success(), "Recursive decryption failed");

    cleanup();
}

#[test]
fn test_profile_manipulation() {
    setup();

    let profile_name: &str = "TEST PROFILE NAME";

    let output = databoxer_cmd!(p "profile new"; profile_name);
    assert!(output.status.success(), "Profile creation failed");

    let output = databoxer_cmd!(p "profile select"; profile_name);
    assert!(output.status.success(), "Profile selection failed");

    let output = databoxer_cmd!("profile get");
    assert!(output.status.success(), "Profile name retrieval failed");
    assert!(output.stdout.len() > 0, "Invalid output for current profile");

    let output = databoxer_cmd!("profile list");
    assert!(output.status.success(), "Profiles list retrieval failed");
    assert!(output.stdout.len() > 0, "Invalid output for the list of existing profiles");

    let output = databoxer_cmd!(p "profile delete"; profile_name);
    assert!(output.status.success(), "Profile deletion failed");

    cleanup();
}

#[test]
fn test_key_generation() {
    setup();

    let test_dir = Path::new(common::TEST_DIR);
    let test_file = test_dir.join("text.txt");

    let output = databoxer_cmd!(p "key new");
    assert!(output.status.success(), "Key generation failed");

    let output = databoxer_cmd!(p "box"; &test_file);
    assert!(output.status.success(), "Encryption failed with generated key");

    let output = databoxer_cmd!(p "unbox"; &test_file);
    assert!(output.status.success(), "Decryption failed with generated key");

    cleanup()
}

#[test]
fn test_key_set() {
    setup();

    let test_dir = Path::new(common::TEST_DIR);
    let test_file = test_dir.join("text.txt");
 
    let key = generate_key();

    let output = databoxer_cmd!(p "key set"; &key);
    assert!(output.status.success(), "Key set failed");

    let output = databoxer_cmd!(p "box"; &test_file);
    assert!(output.status.success(), "Encryption failed with set key");

    let output = databoxer_cmd!(p "unbox"; &test_file);
    assert!(output.status.success(), "Decryption failed with set key");

    cleanup();
}

#[test]
fn test_key_set_from_file() {
    setup();

    let test_dir = Path::new(common::TEST_DIR);
    let key_file_path = test_dir.join("key.txt");
 
    let key = generate_key();

    let mut key_file = File::create(&key_file_path).expect("Unable to create key file");
    key_file.write_all(&key.as_bytes()).expect("Unable to write key data into file");

    let output = databoxer_cmd!(p "key set"; "--file", &key_file_path.to_str().unwrap());
    assert!(output.status.success(), "Key set failed");

    // TODO: create a macro for this type of things
    let mut options = databoxer::options::KeyGetOptions::default();
    let password = common::PASSWORD.to_string();
    options.password = Some(&password);
    let output_key = databoxer::get_key(options).expect("Unable to get current key");
    
    assert_eq!(key, output_key);

    cleanup();
}

#[test]
fn test_invalid_key_set() {
    setup();

    let invalid_key = "KY&*";

    let output = databoxer_cmd!(p "key set"; invalid_key);
    assert!(!output.status.success(), "Invalid key was accepted");

    cleanup();
}

#[test]
fn test_key_get() {
    setup();

    let output = databoxer_cmd!(p "key get");
    assert!(output.status.success(), "Failed to get key");

    cleanup();
}

#[test]
fn test_file_information() {
    setup();
    
    let test_dir = Path::new(common::TEST_DIR);
    let test_file = test_dir.join("text.txt");

    let output = databoxer_cmd!(p "box"; &test_file);
    assert!(output.status.success(), "Text encryption failed");
    
    let output = databoxer_cmd!("information"; &test_file);
    assert!(output.status.success(), "Information retrieval failed");
    
    cleanup();
}