//! Output path policy for the CLI.
//!
//! Core operations are always given an explicit destination, so deciding what an encrypted or a
//! restored file ends up being called belongs to the frontend

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};

use databoxer_core::log;

/// Extension given to every encrypted file
const BOXFILE_EXTENSION: &str = "box";

/// The queue of `--output` paths given on the command line, handed out one per input file. Once it
/// runs dry every remaining file falls back to a derived path
pub struct OutputPaths(Option<VecDeque<PathBuf>>);

impl OutputPaths {
    pub fn new(paths: Option<VecDeque<PathBuf>>) -> Self {
        OutputPaths(paths)
    }

    /// Takes the next supplied output path, if any are left
    pub fn take_next(&mut self) -> Option<PathBuf> {
        let path = self.0.as_mut().and_then(|paths| paths.pop_front());

        if let Some(ref path) = path {
            log!(DEBUG, "Writing to custom output path: {:?}", path);
        }

        path
    }
}

/// Derives the path an encrypted file is written to. The original name is replaced with a random
/// UUID unless it was asked to be kept, and the extension always becomes `.box`
pub fn boxed_path(input: &Path, keep_original_name: bool) -> PathBuf {
    let mut output = input.to_path_buf();

    if !keep_original_name {
        output.set_file_name(uuid::Uuid::new_v4().to_string());
    }

    output.set_extension(BOXFILE_EXTENSION);
    output
}

/// Derives the path a decrypted file is restored to from whatever the boxfile header remembered
/// about the original. Without a recorded name there is nothing to restore to, so one is invented
pub fn restored_path(input: &Path, name: Option<&str>, extension: Option<&str>) -> PathBuf {
    let mut output = input.to_path_buf();

    match name {
        Some(name) => output.set_file_name(name),
        None => {
            log!(WARN, "Original file name is unknown");
            output.set_file_name(uuid::Uuid::new_v4().to_string());
        }
    }

    match extension {
        Some(extension) => {
            output.set_extension(extension);
        },
        None => {
            log!(WARN, "Original file extension is unknown or missing");
            output.set_extension("unboxed");
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn test_boxed_path_keeps_name() {
        let output = boxed_path(Path::new("/tmp/notes.txt"), true);
        assert_eq!(output, PathBuf::from("/tmp/notes.box"));
    }

    #[test]
    fn test_boxed_path_replaces_name() {
        let output = boxed_path(Path::new("/tmp/notes.txt"), false);

        assert_eq!(output.parent(), Some(Path::new("/tmp")));
        assert_eq!(output.extension(), Some(OsStr::new("box")));
        assert_ne!(output.file_stem(), Some(OsStr::new("notes")));
    }

    #[test]
    fn test_restored_path_uses_recorded_metadata() {
        let output = restored_path(Path::new("/tmp/abc-123.box"), Some("notes"), Some("txt"));
        assert_eq!(output, PathBuf::from("/tmp/notes.txt"));
    }

    /// Without a recorded extension the boxfile's own must not be left behind, and the restored
    /// file is marked as having an unknown one rather than being left bare
    #[test]
    fn test_restored_path_without_extension() {
        let output = restored_path(Path::new("/tmp/abc-123.box"), Some("notes"), None);
        assert_eq!(output, PathBuf::from("/tmp/notes.unboxed"));
    }

    /// Without a recorded name there is nothing to restore to, so one gets invented
    #[test]
    fn test_restored_path_without_name() {
        let output = restored_path(Path::new("/tmp/abc-123.box"), None, Some("txt"));

        assert_eq!(output.parent(), Some(Path::new("/tmp")));
        assert_eq!(output.extension(), Some(OsStr::new("txt")));
        assert_ne!(output.file_stem(), Some(OsStr::new("abc-123")));
    }

    #[test]
    fn test_output_paths_hands_out_in_order() {
        let mut outputs = OutputPaths::new(Some(VecDeque::from(vec![
            PathBuf::from("first.box"),
            PathBuf::from("second.box"),
        ])));

        assert_eq!(outputs.take_next(), Some(PathBuf::from("first.box")));
        assert_eq!(outputs.take_next(), Some(PathBuf::from("second.box")));
        assert_eq!(outputs.take_next(), None);
    }

    #[test]
    fn test_output_paths_without_any_supplied() {
        assert_eq!(OutputPaths::new(None).take_next(), None);
    }
}
