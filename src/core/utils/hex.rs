//! Contains HEX manipulation functions for parsing custom types

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
    const HEX_CHARS: &str = "0123456789ABCDEF";
    let mut hex_bytes = vec![0u8; hex_string.len() / 2];

    if hex_string.len() % 2 != 0 {
        return Err(new_err!(InvalidData: InvalidHex, "Length is not a multiple of 2"));
    }
    
    let mut i: usize = 0;
    while i < hex_string.len() {
        // we can just unwrap this since the length is guaranteed to be fine
        let c1: char = hex_string.chars().nth(i).unwrap();
        let c2: char = hex_string.chars().nth(i + 1).unwrap();
        
        if !HEX_CHARS.contains(c1) || !HEX_CHARS.contains(c2) {
            return Err(new_err!(InvalidData: InvalidHex, format!("Invalid byte '{}{}'", c1, c2)))
        }
        
        // we can just unwrap this too since we sanity-checked the characmers beforehand
        hex_bytes[i / 2] = u8::from_str_radix(&format!("{}{}", c1, c2), 16).unwrap();

        i += 2;
    }
    
    Ok(hex_bytes)
}
