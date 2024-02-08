//! Module for Encoding, Encrypting, and Decrypting of PIN Blocks in ISO 9564 Format 4.
//!
//! This module provides functionalities for handling PIN blocks in compliance with the ISO 9564
//! format 4 standard. It offers methods for encoding a Personal Identification Number (PIN) with
//! binding to a Primary Account Number (PAN) into a secure and encrypted PIN block, as well as
//! decrypting and decoding an encoded PIN block to retrieve the original PIN. The encoding,
//! encrypting, and decrypting processes are essential for secure PIN management in financial
//! applications, particularly in areas like ATM and point-of-sale transactions.
//!
//! # Features
//!
//! - **Encoding and Encrypting of PIN and PAN**: This module allows for encoding a PIN and a PAN
//! into a 16-byte PIN block and encrypting it using AES. The encoding process includes setting a
//! control field, encoding the PIN length and digits in Binary Coded Decimal (BCD), and padding
//! with specific values. The second half of the block is filled with a provided random seed.
//!
//! - **Decrypting and Decoding of PIN Blocks**: The module also supports decrypting and decoding
//! of encrypted PIN blocks to extract the original PIN. This process is vital for systems that
//! need to verify or process the PIN at various stages of a transaction.
//!
//! # Example Usage
//!
//! ```
//! use paysec::pin::{encipher_pinblock_iso_4, decipher_pinblock_iso_4};
//! use hex;
//!
//! // Example data for PIN, PAN, random seed, and AES key
//! let key = hex::decode("00112233445566778899AABBCCDDEEFF").expect("Invalid key hex");
//! let pin = "1234";
//! let pan = "1234567890123456789";
//! let rnd_seed = vec![0xFF; 8];
//!
//! // Encrypting the PIN block
//! let encrypted_pin_block = encipher_pinblock_iso_4(&key, pin, pan, rnd_seed).expect("Failed to encipher pinblock");
//! let encrypted_pin_block_hex = hex::encode(encrypted_pin_block.clone()).to_uppercase();
//!
//! // Expected encrypted PIN block in hexadecimal format
//! let expected_pinblock = "28B41FDDD29B743E93124BD8E32D921E";
//!
//! // Asserting the encrypted PIN block matches the expected result
//! assert_eq!(encrypted_pin_block_hex, expected_pinblock, "Failed test for PIN: {}, PAN: {}", pin, pan);
//!
//! // Decrypting the PIN block
//! let decrypted_pin = decipher_pinblock_iso_4(&key, &encrypted_pin_block, pan).expect("Failed to decipher pinblock");
//!
//! // Asserting the decrypted PIN matches the original PIN
//! assert_eq!( decrypted_pin, pin, "Deciphered PIN does not match expected PIN");
//! ```
//!
//! # Disclaimer
//!
//! - This library is provided "as is", with no warranty or guarantees regarding its security or
//! effectiveness in a production environment.
//!
//! # Note
//!
//! - This implementation is suitable for testing and generating test data. It's not intended for
//!   use in production environments, especially where Hardware Security Modules (HSMs) are required.
//! - The random seed must be provided externally, and the library does not assess the quality of
//!   entropy.
//! - For cryptographic operations, this library uses the `soft-aes` crate, which lacks
//!   protections against side-channel attacks. In production, a HSM should be used for cryptographic
//!   operations and random number generation.

use crate::utils::{left_pad_str, right_pad_str, xor_byte_arrays};

use soft_aes::aes::{aes_dec_ecb, aes_enc_ecb};
use std::error::Error;

const ISO4_PIN_BLOCK_LENGTH: usize = 16;

/// Encode a PIN using the ISO 9564 format 4 PIN block standard.
///
/// This function encodes a given Personal Identification Number (PIN) into a
/// 16-byte array according to the ISO 9564 format 4 specification. The encoding
/// process includes setting a control field, encoding the PIN length and digits
/// in Binary Coded Decimal (BCD), and padding with specific values. The second
/// half of the block is filled with a provided random seed.
///
/// # Parameters
///
/// * `pin`: A reference to a string slice representing the ASCII-encoded PIN to
///          be encoded. The PIN must consist of numeric characters only and
///          have a length between 4 and 12 digits.
/// * `rnd_seed`: A byte array representing the random seed used for padding. It
///               must be at least 8 bytes long.
///
/// # Returns
///
/// * `Ok([u8; ISO4_PIN_BLOCK_LENGTH])` - A 16-byte array representing the encoded
///                                       PIN block.
/// * `Err(Box<dyn Error>)` - If the PIN is not within the required length, contains
///                           non-numeric characters, or `rnd_seed` is not 8 bytes long.
///
/// # Errors
///
/// This function will return an error if:
/// - The PIN length is not between 4 and 12 digits.
/// - The PIN contains characters that are not numeric digits.
/// - The provided `rnd_seed` is not exactly 8 bytes long.
pub fn encode_pin_field_iso_4(
    pin: &str,
    rnd_seed: Vec<u8>,
) -> Result<[u8; ISO4_PIN_BLOCK_LENGTH], Box<dyn Error>> {
    const ISO4_PIN_BLOCK_LENGTH: usize = 16;

    if pin.len() < 4 || pin.len() > 12 || !pin.chars().all(char::is_numeric) {
        return Err("PIN BLOCK ISO 4 ERROR: PIN must be between 4 and 12 digits long".into());
    }
    if rnd_seed.len() < 8 {
        return Err("PIN BLOCK ISO 4 ERROR: Random seed must be at least 8 bytes long".into());
    }

    let mut pin_field = [0u8; ISO4_PIN_BLOCK_LENGTH];

    // Control field set to BCD 4, then PIN length
    pin_field[0] = 0x40 | pin.len() as u8;

    // Copy PIN digits as BCD
    for (i, c) in pin.chars().enumerate() {
        let digit = c.to_digit(10).unwrap() as u8;
        pin_field[1 + i / 2] |= if i % 2 == 0 { digit << 4 } else { digit };
    }

    // Remaining nibbles set to 0xA
    for i in pin.len()..14 {
        pin_field[1 + i / 2] |= if i % 2 == 0 { 0xA0 } else { 0x0A };
    }

    // Fill the second half of the block with the first 8 bytes of rnd_seed
    pin_field[8..].copy_from_slice(&rnd_seed[..8]);

    Ok(pin_field)
}

/// Decode a PIN from the ISO 9564 format 4 PIN block.
///
/// This function decodes a Personal Identification Number (PIN) from a
/// 16-byte array according to the ISO 9564 format 4 specification. The decoding
/// process involves verifying the control field, extracting the PIN length and
/// digits from Binary Coded Decimal (BCD), and checking the padding. It ensures
/// the integrity of the PIN block structure.
///
/// # Parameters
///
/// * `pin_field`: A byte slice representing the encoded PIN block. It must be
///                exactly 16 bytes long.
///
/// # Returns
///
/// * `Ok(String)` - A string representing the decoded ASCII-encoded PIN.
/// * `Err(Box<dyn Error>)` - If the PIN block is not 16 bytes long, does not
///                           adhere to the ISO 9564 format 4 standard, or contains
///                           invalid data.
///
/// # Errors
///
/// This function will return an error if:
/// - The PIN block is not exactly 16 bytes long.
/// - The control field is not set to the ISO 9564 format 4 standard.
/// - The PIN length is not between 4 and 12 digits.
/// - The PIN contains non-numeric digits.
/// - The filler bytes are not as per the standard.
pub fn decode_pin_field_iso_4(pin_field: &[u8]) -> Result<String, Box<dyn Error>> {
    if pin_field.len() != 16 {
        return Err("PIN BLOCK ISO 4 ERROR: PIN field must be 16 bytes long".into());
    }

    // Check if the control field is 4 (higher nibble of the first byte)
    if pin_field[0] >> 4 != 0x4 {
        return Err(format!(
            "PIN BLOCK ISO 4 ERROR: PIN block is not ISO format 4: control field `{}`",
            pin_field[0] >> 4
        )
        .into());
    }

    // Extract PIN length (lower nibble of the first byte)
    let pin_len = (pin_field[0] & 0x0F) as usize;

    if pin_len < 4 || pin_len > 12 {
        return Err(format!(
            "PIN BLOCK ISO 4 ERROR: PIN length must be between 4 and 12: `{}`",
            pin_len
        )
        .into());
    }

    let mut pin = String::new();
    for i in 0..pin_len {
        // Extract each digit from the PIN field
        let digit = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if digit > 9 {
            return Err("PIN BLOCK ISO 4 ERROR: PIN contains invalid digit".into());
        }

        pin.push_str(&digit.to_string());
    }

    // Check if the filler is correct (0xA for each unused nibble)
    for i in pin_len..14 {
        let filler = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if filler != 0xA {
            return Err("PIN BLOCK ISO 4 ERROR: PIN block filler is incorrect".into());
        }
    }

    Ok(pin)
}

/// Encode a Primary Account Number (PAN) using the ISO 9564 format 4 PAN block.
///
/// This function encodes a given Primary Account Number (PAN) into a
/// 16-byte array according to the ISO 9564 format 4 specification. The encoding
/// process includes setting a PAN length field and encoding the PAN digits
/// in Binary Coded Decimal (BCD) format. The encoded PAN is used in conjunction
/// with the encoded PIN for secure PIN block generation.
///
/// # Parameters
///
/// * `pan`: A reference to a string slice representing the ASCII-encoded PAN to
///          be encoded. The PAN must consist of numeric characters only and
///          have a length between 1 and 19 digits.
///
/// # Returns
///
/// * `Ok([u8; ISO4_PIN_BLOCK_LENGTH])` - A 16-byte array representing the encoded
///    PAN block.
/// * `Err(Box<dyn Error>)` - If the PAN is not within the required length or
///    contains non-numeric characters.
///
/// # Errors
///
/// This function will return an error if:
/// - The PAN length is not between 1 and 19 digits.
/// - The PAN contains characters that are not numeric digits.
pub fn encode_pan_field_iso_4(pan: &str) -> Result<[u8; 16], Box<dyn Error>> {
    // Check PAN length
    if pan.len() < 1 || pan.len() > 19 || !pan.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long.".into());
    }

    let pan_len = if pan.len() > 12 {
        (pan.len() - 12).to_string()
    } else {
        "0".to_string()
    };

    let pan_padded = left_pad_str(pan, 12, '0');

    let pan_field = pan_len + &pan_padded;

    let pan_field_hex = right_pad_str(&pan_field, 32, '0');

    let pan_bytes = hex::decode(&pan_field_hex)?;

    Ok(pan_bytes
        .as_slice()
        .try_into()
        .expect("Invalid length for conversion"))
}

/// Encipher a PIN block using the ISO 9564 format 4 standard with AES encryption.
///
/// This function takes a PIN and PAN, encodes them according to the ISO 9564 format 4
/// specification, and then encrypts the encoded PIN block. The encryption process binds
/// the PIN with the PAN, improving security. It allows for optional padding or seeding
/// for the PIN block generation, providing flexibility for different security and testing
/// requirements.
///
/// # Parameters
///
/// * `key`: A byte slice representing the AES encryption key.
/// * `pin`: A string slice representing the ASCII-encoded PIN to be encrypted.
/// * `pan`: A string slice representing the ASCII-encoded PAN to be used in the encryption process.
/// * `rnd_seed`: A byte vector representing the random seed used for padding. It
///               must be at least 8 bytes long.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - A `Vec<u8>` representing the encrypted PIN block.
/// * `Err(Box<dyn Error>)` - If there are issues with the input data (e.g., incorrect lengths or non-numeric characters)
///                           or if encryption fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The PIN or PAN is not within the required length or contains non-numeric characters.
/// - The provided padding is not at least 8 bytes long.
/// - There is a failure in the encryption process.
pub fn encipher_pinblock_iso_4(
    key: &[u8],
    pin: &str,
    pan: &str,
    rnd_seed: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Step 1: Encode the PIN and PAN fields
    let pin_field = encode_pin_field_iso_4(pin, rnd_seed)?;
    let pan_field = encode_pan_field_iso_4(pan)?;

    // Step 2: Encrypt the pin field (intermediate block A)
    let intermediate_block_a = aes_enc_ecb(&pin_field, key, None)?;

    // Step 3: XOR intermediate block A with PAN field
    let intermediate_block_b = xor_byte_arrays(&intermediate_block_a, &pan_field)?;

    // Step 4: Encrypt the resulting block (intermediate block B)
    let encrypted_block = aes_enc_ecb(&intermediate_block_b, key, None)?;

    // Step 5: Return the final encrypted pinblock
    Ok(encrypted_block)
}

/// Decipher an ISO 9564 format 4 PIN block using AES decryption.
///
/// This function decrypts an encrypted PIN block and extracts the original PIN. It
/// involves several steps including AES decryption, XOR operations with a PAN-encoded
/// field, and decoding the deciphered PIN field. This process ensures the secure extraction
/// of the PIN from an encrypted PIN block.
///
/// # Parameters
///
/// * `key`: A byte slice representing the AES decryption key.
/// * `pin_block`: A byte slice representing the encrypted PIN block.
/// * `pan`: A string slice representing the ASCII-encoded PAN used in the original PIN block encryption.
///
/// # Returns
///
/// * `Ok(String)` - The decoded PIN as a `String`.
/// * `Err(Box<dyn Error>)` - If the PIN block length is incorrect, if decryption fails, or if the decoded PIN field
///                           is invalid (e.g., incorrect length, non-numeric characters).
///
/// # Errors
///
/// This function will return an error if:
/// - The encrypted PIN block length is not 16 bytes (the AES block size).
/// - There is a failure in the decryption process.
/// - The decoded PIN field is invalid (e.g., incorrect length, non-numeric characters).
pub fn decipher_pinblock_iso_4(
    key: &[u8],
    pin_block: &[u8],
    pan: &str,
) -> Result<String, Box<dyn Error>> {
    if pin_block.len() != 16 {
        return Err(
            "PIN BLOCK ISO 4 ERROR: Data length must be multiple of AES block size 16".into(),
        );
    }

    // Step 1: Decrypt the PIN block (intermediate block B)
    let intermediate_block_b = aes_dec_ecb(pin_block, key, None)?;

    // Step 2: Encode the PAN
    let pan_field = encode_pan_field_iso_4(pan)?;

    // Step 3: XOR intermediate block B with PAN field (intermediate block A)
    let intermediate_block_a = xor_byte_arrays(&intermediate_block_b, &pan_field)?;

    // Step 4: Decrypt intermediate block A to get plaintext PIN field
    let pin_field = aes_dec_ecb(&intermediate_block_a, key, None)?;

    // Step 5: Decode and extract the PIN from the plaintext PIN field
    let pin = decode_pin_field_iso_4(&pin_field)?;

    Ok(pin)
}
