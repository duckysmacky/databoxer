use std::path::Path;
use std::time::SystemTime;
use chrono::{DateTime, Local};
use crate::core::encryption::boxfile::EncryptedField;
use crate::log;

/// Parses the provided boxfile and retrieves original metadata from the header. Returns a vector
/// containing string with retrieved information, skipping the unknown metadata unless specified
/// not to
pub fn get_info(
    input_path: &Path,
    show_unknown: bool
) -> crate::Result<Vec<String>> {
    fn format_time(system_time: SystemTime) -> String {
        let time: DateTime<Local> = system_time.into();
        format!("{}", time.format("%d.%m.%Y %T"))
    }

    log!(INFO, "Getting file information...");
    let boxfile = crate::Boxfile::parse(&input_path)?;
    let header = boxfile.header;

    let mut file_info = Vec::new();

    if header.encrypt_original_data {
        file_info.push("Original file data seems to be encrypted. Unavailable to retrieve file information!".to_string());   
    }

    if let EncryptedField::Plaintext(name) = header.name {
        file_info.push(format!("Name: {:?}", name));
    } else {
        file_info.push("Name: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(extension) = header.extension {
        file_info.push(format!("Extension: {:?}", extension));
    } else {
        file_info.push("Extension: None".to_string());
    }

    if let EncryptedField::Plaintext(source_os) = header.source_os {
        file_info.push(format!("OS: {:?}", source_os));
    } else {
        file_info.push("OS: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(system_time) = header.create_time {
        file_info.push(format!("Create time: {}", format_time(system_time)));
    } else if show_unknown {
        file_info.push("Create time: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(system_time) = header.modify_time {
        file_info.push(format!("Modify time: {}", format_time(system_time)));
    } else if show_unknown {
        file_info.push("Modify time: Unknown".to_string());
    }

    if let EncryptedField::Plaintext(system_time) = header.access_time {
        file_info.push(format!("Access time: {}", format_time(system_time)));
    } else if show_unknown {
        file_info.push("Access time: Unknown".to_string());
    }

    Ok(file_info)
}