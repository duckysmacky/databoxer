//! Contains hex helper functions

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
///
/// The error is a plain message describing what is wrong with the input: there is nothing here for
/// a caller to match on, and whichever domain the hex belongs to supplies the context
pub fn string_to_bytes(hex_string: &str) -> Result<Vec<u8>, String> {
    // operating on bytes rather than chars, as the two only line up for ASCII input
    let input = hex_string.as_bytes();

    if input.len() % 2 != 0 {
        return Err(format!("length ({}) is not a multiple of 2", input.len()));
    }

    let mut hex_bytes = Vec::with_capacity(input.len() / 2);

    for (index, pair) in input.chunks_exact(2).enumerate() {
        match (hex_digit(pair[0]), hex_digit(pair[1])) {
            (Some(high), Some(low)) => hex_bytes.push(high << 4 | low),
            _ => return Err(format!(
                "invalid hex character in byte pair '{}' at index {}",
                String::from_utf8_lossy(pair), index
            ))
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
    fn test_string_to_bytes() -> Result<(), String> {
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
