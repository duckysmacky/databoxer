//! Contains hex helper functions

use crate::{Result, new_err};

/// Transforms and formats a byte array into a hex string
/// (e.g. `[1, 40, 174, 16, 5, ...]` into `"0128AE1005..."`)
pub fn bytes_to_string(bytes: &[u8]) -> String {
    let mut hex_string = String::new();
    for elem in bytes {
        if elem < &0x10 {
            hex_string.push_str(&format!("0{:X}", elem))
        } else {
            hex_string.push_str(&format!("{:X}", elem))
        }
    }
    hex_string
}

/// Transforms formats a hex string into an array of bytes
/// (e.g. `"0128AE1005..."` into `[1, 40, 174, 16, 5, ...`])
pub fn string_to_bytes(hex_string: &str) -> Result<Vec<u8>> {
    // operating on bytes rather than chars, as the two only line up for ASCII input
    let input = hex_string.as_bytes();

    if input.len() % 2 != 0 {
        return Err(new_err!(InvalidData: InvalidHex, hex_string.to_string(); "Length is not a multiple of 2"));
    }

    let mut hex_bytes = Vec::with_capacity(input.len() / 2);

    for pair in input.chunks_exact(2) {
        match (hex_digit(pair[0]), hex_digit(pair[1])) {
            (Some(high), Some(low)) => hex_bytes.push(high << 4 | low),
            _ => {
                let pair = String::from_utf8_lossy(pair);
                return Err(new_err!(InvalidData: InvalidHex, format!("at byte '{}'", pair); "Invalid hex character"));
            }
        }
    }

    Ok(hex_bytes)
}

/// Converts a single hex digit into its numeric value, accepting both cases
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_string() {
        assert_eq!(bytes_to_string(&[1, 40, 174, 16, 5]), "0128AE1005");
    }

    #[test]
    fn test_string_to_bytes() -> Result<()> {
        assert_eq!(string_to_bytes("0128AE1005")?, vec![1, 40, 174, 16, 5]);
        assert_eq!(string_to_bytes("0128ae1005")?, vec![1, 40, 174, 16, 5]);
        assert_eq!(string_to_bytes("")?, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn test_string_to_bytes_rejects_odd_length() {
        assert!(string_to_bytes("ABC").is_err());
    }

    #[test]
    fn test_string_to_bytes_rejects_non_hex() {
        assert!(string_to_bytes("ZZ").is_err());
    }

    #[test]
    fn test_string_to_bytes_rejects_multibyte_characters() {
        assert!(string_to_bytes("ÿ").is_err());
        assert!(string_to_bytes("AAÿ").is_err());
        assert!(string_to_bytes("ÿÿ").is_err());
        assert!(string_to_bytes("日本").is_err());
        assert!(string_to_bytes("𝄞").is_err());
    }
}
