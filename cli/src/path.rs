//! Contains helper functions for path manipulation

use std::{ffi::OsStr, path::{Path, PathBuf}, fs, io};

use databoxer_core::{data::boxfile::Boxfile, log};

/// Opens and parses provided path, returning a flattened list of all found paths. Verifies if the
/// given paths exists. In case of a directory being provided returns all paths inside of it. Can
/// be optionally be marked to search recursively all files within all inner directories.
pub fn parse_paths(input_paths: Vec<PathBuf>, recursive: bool) -> Vec<PathBuf> {
    let mut file_paths: Vec<PathBuf> = Vec::new();

    for path in input_paths {
        if path.is_dir() {
            if let Err(err) = read_dir(&path, &mut file_paths, recursive) {
                log!(ERROR, "Unable to read the directory '{}': {}", path.display(), err);
            }
        } else if path.is_file() {
            file_paths.push(path);
        } else if !path.exists() {
            // the file may have been boxed already, in which case it lives under a different name
            match search_for_original(&path) {
                Some(box_path) => file_paths.push(box_path),
                None => log!(ERROR, "Unable to find '{}'", path.display())
            }
        }
    }
    file_paths
}

fn read_dir(dir_path: &Path, file_paths: &mut Vec<PathBuf>, recursive: bool) -> io::Result<()> {
    for entry in fs::read_dir(dir_path)? {
        let path = entry?.path();

        if path.is_dir() && recursive {
            read_dir(&path, file_paths, true)?;
        } else if path.is_file() {
            file_paths.push(path);
        }
    }

    Ok(())
}

/// Searches the `.box` files next to a missing path for one which remembers it as its original
/// name. Anything which cannot be read or parsed is simply not a match
fn search_for_original(missing_path: &Path) -> Option<PathBuf> {
    let target_name = missing_path.file_stem()?.to_string_lossy().to_string();
    let dir_path = missing_path.parent()?;

    for entry in fs::read_dir(dir_path).ok()? {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(_) => continue
        };

        if !path.is_file() || path.extension() != Some(OsStr::new("box")) {
            continue;
        }

        let boxfile = match Boxfile::parse(&path) {
            Ok(boxfile) => boxfile,
            Err(_) => continue
        };

        if boxfile.metadata().name.as_deref() == Some(target_name.as_str()) {
            log!(INFO, "Found an encrypted (.box) file with the same original name: {}", path.display());
            return Some(path)
        }
    }

    None
}
