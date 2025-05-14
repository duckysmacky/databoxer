//! Contains functions for basic IO operation on files

use std::path::Path;
use std::fs::{self, File};
use std::io::{Read, Result, Write};
use crate::log;

/// Reads plain bytes from the specified file
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    log!(DEBUG, "Reading bytes from '{}'", path.display());
    let mut file = File::open(path)?;
    let metadata = fs::metadata(path)?;
    let mut buffer = vec![0; metadata.len() as usize];

    file.read(&mut buffer)?;
    file.flush()?;

    log!(DEBUG, "Read {} bytes", buffer.len());
    Ok(buffer)
}

/// Reads specified file and returns its contents as string
pub fn read_file(file_path: &Path) -> Result<String> {
    log!(DEBUG, "Reading '{}'", file_path.display());
    let mut file = File::open(&file_path)?;
    let mut file_contents = String::new();

    file.read_to_string(&mut file_contents)?;

    Ok(file_contents)
}

/// Writes plain bytes to the specified file. Creates a new one if already doesn't exist
pub fn write_bytes(path: &Path, bytes: &[u8], truncate: bool) -> Result<()> {
    log!(DEBUG, "Writing bytes to '{}'", path.display());
    let mut file = File::options()
        .write(true)
        .create(true)
        .truncate(truncate)
        .open(&path)?;

    file.write_all(bytes)?;
    file.flush()?;

    log!(DEBUG, "Wrote {} bytes", bytes.len());
    Ok(())
}

/// Writes string to the specified file. Creates a new one if already doesn't exist
pub fn write_file(path: &Path, contents: &str, truncate: bool) -> Result<()> {
    log!(DEBUG, "Writing to '{}'", path.display());
    let mut file = File::options()
        .write(true)
        .create(true)
        .truncate(truncate)
        .open(&path)?;

    file.write_all(contents.as_bytes())?;
    file.flush()?;

    Ok(())
}