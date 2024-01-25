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
#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_encode_pin_field_iso_4_various_pins() {
        let test_cases = [
            (
                "12345",
                "517F9481BA5275FA",
                "4512345AAAAAAAAA517F9481BA5275FA",
            ),
            (
                "1234567",
                "CAF92E156B7D4489",
                "471234567AAAAAAACAF92E156B7D4489",
            ),
            (
                "12345678",
                "424D0369B23E2B4C00",
                "4812345678AAAAAA424D0369B23E2B4C",
            ),
            (
                "12345678901",
                "9B263A096EA64687010203",
                "4B12345678901AAA9B263A096EA64687",
            ),
            (
                "123456789012",
                "8A268C65E92C3B39AABBCCDDEEFF",
                "4C123456789012AA8A268C65E92C3B39",
            ),
        ];

        for (pin, rnd_seed_hex, expected_hex) in test_cases {
            let rnd_seed = hex::decode(rnd_seed_hex).unwrap();
            let expected_result = hex::decode(expected_hex).unwrap();

            // Convert Vec<u8> to [u8; 16]
            let mut expected_bytes = [0u8; 16];
            expected_bytes.copy_from_slice(&expected_result);

            assert_eq!(
                encode_pin_field_iso_4(pin, rnd_seed).unwrap(),
                expected_bytes,
                "Failed test for PIN: {}",
                pin
            );
        }
    }

    #[test]
    fn test_encode_pin_field_iso_4_invalid_pin_length() {
        // Test case: PIN length is less than 4, should return an error.
        let pin = "123";
        let rnd_seed = decode("0000000000000000").unwrap();
        assert!(matches!(encode_pin_field_iso_4(pin, rnd_seed), Err(_)));

        // Test case: PIN length is greater than 12, should return an error.
        let pin = "1234567890123";
        let rnd_seed = decode("0000000000000000").unwrap();
        assert!(matches!(encode_pin_field_iso_4(pin, rnd_seed), Err(_)));
    }

    #[test]
    fn test_encode_pin_field_iso_4_non_numeric_pin() {
        // Test case: PIN contains non-numeric characters, should return an error.
        let pin = "12A4";
        let rnd_seed = decode("0000000000000000").unwrap();
        assert!(matches!(encode_pin_field_iso_4(pin, rnd_seed), Err(_)));
    }

    #[test]
    fn test_encode_pin_field_iso_4_invalid_rnd_seed_length() {
        // Test case: rnd_seed is not exactly 8 bytes long, should return an error.
        let pin = "1234";
        let rnd_seed = decode("00000000").unwrap(); // Invalid length
        assert!(matches!(encode_pin_field_iso_4(pin, rnd_seed), Err(_)));
    }

    #[test]
    fn test_encode_pin_field_iso_4_too_short() {
        let pin = "123"; // Too short
        let rnd_seed = vec![0u8; 8];
        let result = encode_pin_field_iso_4(pin, rnd_seed);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PIN BLOCK ISO 4 ERROR: PIN must be between 4 and 12 digits long"
        );
    }

    #[test]
    fn test_encode_pin_field_iso_4_too_long() {
        let pin = "1234567890123"; // Too long
        let rnd_seed = vec![0u8; 8];
        let result = encode_pin_field_iso_4(pin, rnd_seed);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PIN BLOCK ISO 4 ERROR: PIN must be between 4 and 12 digits long"
        );
    }
}
