//! Module for Encoding and Decoding of PIN Blocks in ISO 9564 Format 3.
//!
//! This module provides functionalities for handling PIN blocks in compliance with the ISO 9564
//! format 3 standard. It offers methods for encoding a Personal Identification Number (PIN) with
//! bindint to a Primary Account Number (PAN) into a secure PIN block, as well as decoding an
//! encoded PIN block to retrieve the original PIN. The encoding and decoding processes are
//! essential for secure PIN management in financial applications, particularly in the areas of ATM
//! and point-of-sale transactions.
//!
//! # Features
//!
//! - **Encoding of PIN and PAN**: This module allows for encoding a PIN and a PAN into an 8-byte PIN block.
//!   The PIN is encoded with additional security measures, including a control field, BCD encoding, and padding
//!   with hexadecimal characters derived from a random seed.
//!
//! - **Decoding of PIN Blocks**: The module also supports decoding of encoded PIN blocks to extract the original PIN.
//!   This process is vital for systems that need to verify or process the PIN at various stages of a transaction.
//!
//! - **Support for Custom Random Seeds**: For testing purposes, the module allows the use of custom random seeds
//!   for generating part of the PIN field during the encoding process.
//!
//! # Example Usage
//!
//! ```
//! use paysec::pin::{encode_pinblock_iso_3, decode_pinblock_iso_3};
//! use hex;
//!
//! // Example data for PIN, PAN, and random seed
//! let pin = "1234";
//! let pan = "12345678901234";
//! let rnd_seed = vec![0xFF; 8];
//!
//! // Encoding the PIN block
//! let pin_block = encode_pinblock_iso_3(pin, pan, rnd_seed.clone()).unwrap();
//! let pin_block_hex = hex::encode_upper(pin_block);
//!
//! // Expected encoded PIN block in hexadecimal format
//! let expected_pinblock = "341217BA9876FEDC";
//!
//! // Asserting the encoded PIN block matches the expected result
//! assert_eq!(
//!     pin_block_hex, expected_pinblock,
//!     "Failed test for PIN: {}, PAN: {}",
//!     pin, pan
//! );
//!
//! // Decoding the PIN block
//! let decoded_pin =
//!     decode_pinblock_iso_3(&pin_block, pan).expect("Failed to decode PIN block");
//!
//! // Asserting the decoded PIN matches the original PIN
//! assert_eq!(
//!     decoded_pin, pin,
//!     "Decoded PIN does not match for PIN: {}, PAN: {}",
//!     pin, pan
//! );
//! ```
//!
//! # Disclaimer
//!
//! - This library is provided "as is", with no warranty or guarantees regarding its security or
//!   effectiveness in a production environment.
//!
//! # Note
//!
//! - This implementation is suitable for testing and generating test data. It's not intended for
//!   use in production environments, especially where Hardware Security Modules (HSMs) are required.
//! - The random seed must be provided externally, and the library does not assess the quality of
//!   entropy.

use crate::utils::{transform_nibbles_to_af, xor_byte_arrays};
use std::error::Error;

const ISO3_PIN_BLOCK_LENGTH: usize = 8;

/// Encode a PIN block using the ISO 9564 format 3 standard.
///
/// This function takes a PIN and a PAN, encodes them separately according to the ISO 9564 format 3
/// specification, and then combines them using an XOR operation. The resulting PIN block is a
/// secure way to bind the PIN with the associated PAN. The function allows for a custom random
/// seed to be used for generating part of the PIN block.
///
/// # Parameters
///
/// * `pin`: A reference to a string slice representing the ASCII-encoded PIN to be used in
///          the PIN block. The PIN must consist of numeric characters only and have a length
///          between 4 and 12 digits.
/// * `pan`: A reference to a string slice representing the ASCII-encoded PAN associated with
///          the PIN. The PAN must consist of numeric characters only and be at least 13 digits long.
/// * `rnd_seed`: A vector of bytes representing the random seed used for generating part of
///               the PIN field.
///
/// # Returns
///
/// * `Ok([u8; ISO3_PIN_BLOCK_LENGTH])` - An 8-byte array representing the encoded PIN block.
/// * `Err(Box<dyn Error>)` - If there are issues with the input data (e.g., incorrect lengths
///                           or non-numeric characters), or if the XOR operation fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The PIN length is not between 4 and 12 digits.
/// - The PAN length is less than 13 digits.
/// - The PIN or PAN contains non-numeric characters.
/// - The XOR operation fails for any reason.
///
/// # Note
///
/// This function encodes and combines the PIN and PAN fields but does not encrypt the resulting
/// PIN block. The encoded PIN block should be encrypted in a separate step using an encryption
/// algorithm like Triple DES for secure handling and transmission.
pub fn encode_pinblock_iso_3(
    pin: &str,
    pan: &str,
    rnd_seed: Vec<u8>,
) -> Result<[u8; ISO3_PIN_BLOCK_LENGTH], Box<dyn Error>> {
    const ISO3_PIN_BLOCK_LENGTH: usize = 8;

    let pin_field = encode_pin_field_iso_3(&pin, &rnd_seed)?;

    let pan_field = encode_pan_field_iso_3(&pan)?;

    // XOR the pin_field and pan_field
    let pin_block = xor_byte_arrays(&pin_field, &pan_field)?;

    Ok(pin_block.try_into().unwrap_or_else(|_| {
        panic!(
            "Failed to convert the result into an array of length {}",
            ISO3_PIN_BLOCK_LENGTH
        )
    }))
}

/// Decode a PIN block using the ISO 9564 format 3 standard and extract the PIN.
///
/// This function takes an encoded PIN block and a PAN, decodes them separately
/// according to the ISO 9564 format 3 specification, and then extracts the PIN.
/// The process involves creating a PAN field, XOR-ing it with the PIN block,
/// and then decoding the resulting field to extract the PIN.
///
/// # Parameters
///
/// * `pin_block`: A byte slice representing the encoded PIN block.
/// * `pan`: A reference to a string slice representing the ASCII-encoded PAN associated with
///          the PIN. The PAN must consist of numeric characters only and be at least 13 digits long.
///
/// # Returns
///
/// * `Ok(String)` - A string representing the decoded PIN.
/// * `Err(Box<dyn Error>)` - If there are issues with the input data or if decoding fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The PAN length is less than 13 digits.
/// - The PAN contains non-numeric characters.
/// - The decoding process fails for any reason.
pub fn decode_pinblock_iso_3(pin_block: &[u8], pan: &str) -> Result<String, Box<dyn Error>> {
    // Ensure the pinblock length is 8 bytes
    if pin_block.len() != 8 {
        return Err("PIN BLOCK ISO 3 ERROR: Invalid PIN block length".into());
    }

    // Create PAN block
    let pan_field = encode_pan_field_iso_3(pan)?;

    // XOR the pin_block and pan_block
    let pin_field = xor_byte_arrays(pin_block, &pan_field)?;

    // Decode the pin_field to extract the PIN
    let pin = decode_pin_field_iso_3(&pin_field)?;

    Ok(pin)
}

/// Encode a PIN field using the ISO 9564 format 3 PIN block standard.
///
/// This function encodes a given Personal Identification Number (PIN) into an 8-byte array
/// according to the ISO 9564 format 3 specification. The encoding process includes setting a
/// control field, encoding the PIN length and digits in Binary Coded Decimal (BCD), and padding
/// with hexadecimal characters from A to F. The padding is derived from a provided random seed,
/// ensuring variability and security.
///
/// # Parameters
///
/// * `pin`: A reference to a string slice representing the ASCII-encoded PIN to
///          be encoded. The PIN must consist of numeric characters only and
///          have a length between 4 and 12 digits.
/// * `rnd_seed`: A reference to a vector of bytes representing the random seed used
///               for padding. The first 8 bytes of the seed are transformed to ensure
///               they fall within the hexadecimal range A to F.
///
/// # Returns
///
/// * `Ok([u8; ISO3_PIN_BLOCK_LENGTH])` - An 8-byte array representing the encoded
///                                       PIN block.
/// * `Err(Box<dyn Error>)` - If the PIN is not within the required length, contains
///                           non-numeric characters, or if there are issues with the
///                           random seed.
///
/// # Errors
///
/// This function will return an error if:
/// - The PIN length is not between 4 and 12 digits.
/// - The PIN contains characters that are not numeric digits.
/// - The provided `rnd_seed` does not have at least 8 bytes.
pub fn encode_pin_field_iso_3(
    pin: &str,
    rnd_seed: &Vec<u8>,
) -> Result<[u8; ISO3_PIN_BLOCK_LENGTH], Box<dyn Error>> {
    // Validate PIN
    if pin.len() < 4 || pin.len() > 12 || !pin.chars().all(char::is_numeric) {
        return Err("PIN BLOCK ISO 3 ERROR: PIN must be between 4 and 12 digits long".into());
    }

    // Transform the first 8 bytes of the random seed to the A-F range
    let transformed_seed = transform_nibbles_to_af(&rnd_seed);

    // Ensure we have at least 8 bytes to avoid panics
    if transformed_seed.len() < ISO3_PIN_BLOCK_LENGTH {
        return Err("PIN BLOCK ISO 3 ERROR: Insufficient seed length for PIN block".into());
    }

    let mut pin_field = [0u8; ISO3_PIN_BLOCK_LENGTH];
    pin_field.copy_from_slice(&transformed_seed[..ISO3_PIN_BLOCK_LENGTH]);

    // Control field (3) and PIN length into the first byte as nibbles
    pin_field[0] = 0x30 | pin.len() as u8;

    // Process PIN digits
    for (i, c) in pin.chars().enumerate() {
        let digit = c.to_digit(10).unwrap() as u8;

        if i % 2 == 0 {
            // Even index: place digit in the high nibble of the byte, preserve low nibble
            pin_field[1 + i / 2] = (pin_field[1 + i / 2] & 0x0F) | (digit << 4);
        } else {
            // Odd index: place digit in the low nibble of the byte, preserve high nibble
            pin_field[1 + i / 2] = (pin_field[1 + i / 2] & 0xF0) | digit;
        }
    }

    Ok(pin_field)
}

/// Decodes a PIN field encoded in ISO 9564 format 3.
///
/// This function takes a byte array representing the encoded PIN field
/// and decodes it to extract the PIN. It checks the format of the field
/// and extracts the PIN length and digits.
///
/// # Parameters
///
/// * `pin_field`: A byte slice representing the encoded PIN field.
///
/// # Returns
///
/// * `Ok(String)` - A string representing the decoded PIN.
/// * `Err(Box<dyn Error>)` - If the PIN field is not in the correct format or if decoding fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The PIN field is not in ISO 9564 format 3.
/// - The PIN length is not between 4 and 12 digits.
/// - The filler characters are not within the expected range (A-F).
/// - The PIN is not numeric.
pub fn decode_pin_field_iso_3(pin_field: &[u8]) -> Result<String, Box<dyn Error>> {
    if pin_field.len() != 8 {
        return Err("PIN BLOCK ISO 3 ERROR: PIN field must be 8 bytes long".into());
    }

    if (pin_field[0] >> 4) != 0x3 {
        return Err("PIN BLOCK ISO 3 ERROR: PIN block is not ISO format 3.".into());
    }

    let pin_len = (pin_field[0] & 0x0F) as usize;

    if pin_len < 4 || pin_len > 12 {
        return Err("PIN BLOCK ISO 3 ERROR: PIN length must be between 4 and 12".into());
    }

    let mut pin = String::new();
    for i in 0..pin_len {
        let digit = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if digit > 9 {
            return Err("PIN BLOCK ISO 3 ERROR: PIN contains invalid digit".into());
        }

        pin.push_str(&digit.to_string());
    }

    // Check if the filler is correct (A-F for each unused nibble)
    for i in pin_len..14 {
        let filler = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if !(0xA..=0xF).contains(&filler) {
            return Err("PIN BLOCK ISO 3 ERROR: PIN block filler is incorrect".into());
        }
    }

    Ok(pin)
}

/// Encode a Primary Account Number (PAN) using the ISO 9564 format 3 PAN field.
///
/// This function encodes a given PAN into an 8-byte array as per the ISO 9564 format 3
/// specification. The encoding involves extracting the last 12 digits of the PAN (excluding the
/// check digit), and converting these digits into Binary Coded Decimal (BCD) format. The first two
/// bytes of the 8-byte array are set to zero, and the BCD digits are placed starting from the
/// third byte.
///
/// # Parameters
///
/// * `pan`: A reference to a string slice representing the ASCII-encoded PAN to be encoded.
///          The PAN must consist of numeric characters only and have a length of at least 13 digits
///          to ensure there are 12 digits excluding the check digit.
///
/// # Returns
///
/// * `Ok([u8; ISO3_PIN_BLOCK_LENGTH])` - An 8-byte array representing the encoded PAN block.
/// * `Err(Box<dyn Error>)` - If the PAN is shorter than the required length or contains non-numeric characters.
///
/// # Errors
///
/// This function will return an error if:
/// - The PAN is shorter than 13 digits (to ensure at least 12 digits excluding the check digit).
/// - The PAN contains characters that are not numeric digits.
pub fn encode_pan_field_iso_3(pan: &str) -> Result<[u8; ISO3_PIN_BLOCK_LENGTH], Box<dyn Error>> {
    // Ensure PAN length is at least 13 digits (to have 12 digits excluding the check digit)
    if pan.len() < 13 {
        return Err(
            "PIN BLOCK ISO 3 ERROR: PAN must be at least 13 digits long for ISO 3 encoding".into(),
        );
    }

    // Extract the last 12 digits of the PAN, excluding the check digit
    let pan_last_12 = &pan[pan.len() - 13..pan.len() - 1];

    // Initialize pan_field with the first two bytes set to 0
    let mut pan_field = [0u8; ISO3_PIN_BLOCK_LENGTH];

    // Convert the last 12 digits of PAN to BCD and place into pan_field
    for (i, digit_char) in pan_last_12.chars().enumerate() {
        let digit = digit_char.to_digit(10).ok_or("Invalid digit in PAN")? as u8;

        if i % 2 == 0 {
            // Even index: place digit in the high nibble
            pan_field[2 + i / 2] = digit << 4;
        } else {
            // Odd index: place digit in the low nibble
            pan_field[2 + i / 2] |= digit;
        }
    }

    Ok(pan_field)
}
