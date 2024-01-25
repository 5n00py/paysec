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

    #[test]
    fn test_decode_pin_field_iso_4_various_pins() {
        let test_cases = [
            ("12345", "4512345AAAAAAAAA517F9481BA5275FA"),
            ("1234567", "471234567AAAAAAACAF92E156B7D4489"),
            ("12345678", "4812345678AAAAAA424D0369B23E2B4C"),
            ("12345678901", "4B12345678901AAA9B263A096EA64687"),
            ("123456789012", "4C123456789012AA8A268C65E92C3B39"),
        ];

        for (expected_pin, encoded_hex) in test_cases {
            let encoded_bytes = hex::decode(encoded_hex).unwrap();
            assert_eq!(
                decode_pin_field_iso_4(&encoded_bytes).unwrap(),
                expected_pin,
                "Failed test for encoded PIN field: {}",
                encoded_hex
            );
        }
    }

    #[test]
    fn test_decode_pin_field_iso_4_invalid_length() {
        let pin_field = vec![0u8; 15]; // Less than 16 bytes
        assert!(matches!(
            decode_pin_field_iso_4(&pin_field),
            Err(e) if e.to_string() == "PIN BLOCK ISO 4 ERROR: PIN field must be 16 bytes long"
        ));
    }

    #[test]
    fn test_decode_pin_field_iso_4_invalid_control_field() {
        let mut pin_field = vec![0u8; 16];
        pin_field[0] = 0x30; // Control field not 4
        assert!(matches!(
            decode_pin_field_iso_4(&pin_field),
            Err(e) if e.to_string().contains("PIN block is not ISO format 4: control field")
        ));
    }

    #[test]
    fn test_decode_pin_field_iso_4_invalid_pin_length() {
        let pin_field = vec![0x40; 16]; // PIN length 0
        assert!(matches!(
            decode_pin_field_iso_4(&pin_field),
            Err(e) if e.to_string().contains("PIN length must be between 4 and 12")
        ));
    }

    #[test]
    fn test_decode_pin_field_iso_4_non_numeric_pin() {
        let pin_field = vec![
            0x44, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA,
        ];
        assert!(matches!(
            decode_pin_field_iso_4(&pin_field),
            Err(e) if e.to_string() == "PIN BLOCK ISO 4 ERROR: PIN contains invalid digit"
        ));
    }

    #[test]
    fn test_decode_pin_field_iso_4_invalid_filler() {
        let pin_field = vec![
            0x44, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]; // Filler not 0xA
        assert!(matches!(
            decode_pin_field_iso_4(&pin_field),
            Err(e) if e.to_string() == "PIN BLOCK ISO 4 ERROR: PIN block filler is incorrect"
        ));
    }

    #[test]
    fn test_encode_pan_field_iso_4_various_pans() {
        let test_cases = [
            ("1", "00000000000010000000000000000000"),
            ("12", "00000000000120000000000000000000"),
            ("123", "00000000001230000000000000000000"),
            ("1234", "00000000012340000000000000000000"),
            ("1234567890", "00012345678900000000000000000000"),
            ("123456789012", "01234567890120000000000000000000"),
            ("1234567890123", "11234567890123000000000000000000"),
            ("12345678901234", "21234567890123400000000000000000"),
            ("123456789012345", "31234567890123450000000000000000"),
            ("1234567890123456", "41234567890123456000000000000000"),
            ("12345678901234567", "51234567890123456700000000000000"),
            ("123456789012345678", "61234567890123456780000000000000"),
            ("1234567890123456789", "71234567890123456789000000000000"),
        ];

        for (pan, expected_hex) in test_cases {
            let expected_result = hex::decode(expected_hex).unwrap();

            // Convert Vec<u8> to [u8; 16]
            let mut expected_bytes = [0u8; 16];
            expected_bytes.copy_from_slice(&expected_result);

            assert_eq!(
                encode_pan_field_iso_4(pan).unwrap(),
                expected_bytes,
                "Failed test for PAN: {}",
                pan
            );
        }
    }

    #[test]
    fn test_encode_pan_field_iso_4_too_short() {
        let pan = ""; // Too short
        let result = encode_pan_field_iso_4(pan);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long."
        );
    }

    #[test]
    fn test_encode_pan_field_iso_4_too_long() {
        let pan = "12345678901234567890"; // Too long
        let result = encode_pan_field_iso_4(pan);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long."
        );
    }

    #[test]
    fn test_encode_pan_field_iso_4_invalid_char() {
        let pan = "123456789x123456789"; // Too long
        let result = encode_pan_field_iso_4(pan);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long."
        );
    }

    #[test]
    fn test_encipher_pinblock_iso_4_valid() {
        let key = hex::decode("00112233445566778899AABBCCDDEEFF").expect("Invalid key hex");
        let pin = "1234";
        let pan = "1234567890123456789";
        let expected_pin_block = "28B41FDDD29B743E93124BD8E32D921E";

        let rnd_seed = vec![0xFF; 8];

        let result =
            encipher_pinblock_iso_4(&key, pin, pan, rnd_seed).expect("Failed to encipher pinblock");
        let result_hex = hex::encode(result).to_uppercase();

        assert_eq!(result_hex, expected_pin_block);
    }

    #[test]
    fn test_decipher_pinblock_iso_4_various() {
        let key = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

        let test_cases = [
            (
                "1234",
                "1234567890123456",
                "52DB178C6EDCE52E3A70F7FBC8E9C758",
            ),
            (
                "123456",
                "123456789012345678",
                "847A0209C659E4C4A79CA6A2A2217D31",
            ),
            (
                "12345678",
                "1234567890123456789",
                "018BFEC8B5EF60181A327AD8325A2BA4",
            ),
        ];

        for (expected_pin, pan, encrypted_pin_block_hex) in test_cases {
            let encrypted_pin_block = hex::decode(encrypted_pin_block_hex).unwrap();
            let decrypted_pin = decipher_pinblock_iso_4(&key, &encrypted_pin_block, pan)
                .expect("Failed to decipher pinblock");
            assert_eq!(
                decrypted_pin, expected_pin,
                "Deciphered PIN does not match expected PIN"
            );
        }
    }
}
