//! Contains helper functions for path manipulation

use std::fs;
use std::path::{Path, PathBuf};
use crate::core::data::boxfile;
use crate::{log, new_err, Result};

/// Opens and parses provided path, returning a flattened list of all found paths. Verifies if the
/// given paths exists. In case of a directory being provided returns all paths inside of it. Can
/// be optionally be marked to search recursively all files within all inner directories.
pub fn parse_paths(input_paths: Vec<PathBuf>, recursive: bool) -> Vec<PathBuf> {
    let mut file_paths: Vec<PathBuf> = Vec::new();

    for path in input_paths {
        if path.is_dir() {
            if let Err(_) = read_dir(&path, &mut file_paths, recursive) {
                // TODO: improve error handling
                continue;
            }
        } else if path.is_file() {
            file_paths.push(path);
        } else if !path.exists() {
            let target_name = match path.file_stem() {
                Some(name) => name.to_string_lossy().to_string(),
                None => {
                    log!(ERROR, "Unable to find '{}'", path.display());
                    continue;
                }
            };

            match search_for_original(path.parent().unwrap(), target_name) {
                Ok(box_path) => file_paths.push(box_path),
                Err(_) => {
                    log!(ERROR, "Unable to find '{}'", path.display());
                    continue;
                }
            }
        }
    }
    file_paths
}

fn read_dir(dir_path: &Path, file_paths: &mut Vec<PathBuf>, recursive: bool) -> Result<()> {
    for entry in fs::read_dir(dir_path).map_err(|e| new_err!(IOError: Read, dir_path.into(); e))? {
        let path = entry.map_err(|e| new_err!(IOError: Misc; e))?.path();

        if path.is_dir() && recursive {
            read_dir(&path, file_paths, true)?;
        } else if path.is_file() {
            file_paths.push(path);
        }
    }

    Ok(())
}

/// Searches `.box` files within a directory for one which matches its original name with provided
fn search_for_original(dir_path: &Path, target_name: String) -> Result<PathBuf> {
    for entry in fs::read_dir(dir_path).map_err(|e| new_err!(IOError: Read, dir_path.into(); e))? {
        let path = entry.map_err(|e| new_err!(IOError: Misc; e))?.path();

        if !path.is_file() || path.extension().is_none() { continue; }
        if let Some(ext) = path.extension() {
            if ext != "box" { continue; }
        } 

        let boxfile = boxfile::Boxfile::parse(&path)?;
        let (original_name, _) = boxfile.file_info();

        if let Some(name) = original_name {
            if target_name.eq(name) {
                log!(INFO, "Found an encrypted (.box) file with the same original name: {}", path.display());
                return Ok(path)
            }
        }
    }

    Err(new_err!(IOError: NotFound, target_name.into(); "No matching .box file found"))
}
