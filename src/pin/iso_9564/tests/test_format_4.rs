use crate::pin::*;
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
        0x44, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA,
    ];
    assert!(matches!(
        decode_pin_field_iso_4(&pin_field),
        Err(e) if e.to_string() == "PIN BLOCK ISO 4 ERROR: PIN contains invalid digit"
    ));
}

#[test]
fn test_decode_pin_field_iso_4_invalid_filler() {
    let pin_field = vec![
        0x44, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
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
