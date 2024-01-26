use crate::pin::*;
use hex::FromHex;

#[test]
fn test_encode_pin_field_iso_3() {
    let test_cases = [
        ("1234", vec![0xFF; 8], "341234FFFFFFFFFF"),
        ("12345", vec![0x55; 8], "3512345FFFFFFFFF"),
        ("123456", vec![0x99; 8], "36123456FFFFFFFF"),
        ("1234567", vec![0xAA; 8], "371234567AAAAAAA"),
        ("123455678", vec![0x00; 8], "39123455678AAAAA"),
        ("123456789", vec![0x11; 8], "39123456789BBBBB"),
        ("1234567890", vec![0x66; 8], "3A1234567890CCCC"),
        ("12345678901", vec![0xAA; 8], "3B12345678901AAA"),
        ("123456789012", vec![0xAA; 8], "3C123456789012AA"),
    ];

    for (pin, rnd_seed, expected_hex) in test_cases {
        let encoded = encode_pin_field_iso_3(pin, &rnd_seed).unwrap();
        let encoded_hex = hex::encode(encoded);

        assert_eq!(
            encoded_hex.to_uppercase(),
            expected_hex,
            "Failed test for PIN: {}",
            pin
        );
    }
}

#[test]
fn test_encode_pin_field_iso_3_invalid_pin_length() {
    let short_pin = "123"; // Less than 4 digits
    let long_pin = "1234567890123"; // More than 12 digits
    let rnd_seed = vec![0xFF; 8];

    let error_short = encode_pin_field_iso_3(short_pin, &rnd_seed)
        .unwrap_err()
        .to_string();
    let error_long = encode_pin_field_iso_3(long_pin, &rnd_seed)
        .unwrap_err()
        .to_string();

    assert_eq!(
        error_short,
        "PIN BLOCK ISO 3 ERROR: PIN must be between 4 and 12 digits long"
    );
    assert_eq!(
        error_long,
        "PIN BLOCK ISO 3 ERROR: PIN must be between 4 and 12 digits long"
    );
}

#[test]
fn test_encode_pin_field_iso_3_non_numeric_pin() {
    let non_numeric_pin = "123A";
    let rnd_seed = vec![0xFF; 8];

    let error = encode_pin_field_iso_3(non_numeric_pin, &rnd_seed)
        .unwrap_err()
        .to_string();

    assert_eq!(
        error,
        "PIN BLOCK ISO 3 ERROR: PIN must be between 4 and 12 digits long"
    );
}

#[test]
fn test_encode_pin_field_iso_3_insufficient_seed_length() {
    let pin = "1234";
    let short_seed = vec![0xFF; 7]; // Less than 8 bytes

    let error = encode_pin_field_iso_3(pin, &short_seed)
        .unwrap_err()
        .to_string();

    assert_eq!(
        error,
        "PIN BLOCK ISO 3 ERROR: Insufficient seed length for PIN block"
    );
}

#[test]
fn test_decode_pin_field_iso_3() {
    let test_cases = [
        ("341234FFFFFFFFFF", "1234"),
        ("3512345FFFFFFFFF", "12345"),
        ("36123456FFFFFFFF", "123456"),
        ("371234567AAAAAAA", "1234567"),
        ("39123455678AAAAA", "123455678"),
        ("39123456789BBBBB", "123456789"),
        ("3A1234567890CCCC", "1234567890"),
        ("3B12345678901AAA", "12345678901"),
        ("3C123456789012AA", "123456789012"),
    ];

    for (encoded_hex, expected_pin) in test_cases {
        let pin_field = hex::decode(encoded_hex).expect("Invalid hex in test data");
        let decoded_pin = decode_pin_field_iso_3(&pin_field).expect("Decoding failed");

        assert_eq!(
            decoded_pin, expected_pin,
            "Failed to decode PIN correctly for encoded hex: {}",
            encoded_hex
        );
    }
}

#[test]
fn test_decode_pin_field_iso_3_invalid_control_field() {
    let invalid_control_field = hex::decode("441234FFFFFFFFFF").unwrap();
    assert_eq!(
        decode_pin_field_iso_3(&invalid_control_field)
            .unwrap_err()
            .to_string(),
        "PIN BLOCK ISO 3 ERROR: PIN block is not ISO format 3."
    );
}

#[test]
fn test_decode_pin_field_iso_3_invalid_pin_length() {
    let invalid_pin_length = hex::decode("3D123456FFFFFFFF").unwrap(); // Length: 13
    assert_eq!(
        decode_pin_field_iso_3(&invalid_pin_length)
            .unwrap_err()
            .to_string(),
        "PIN BLOCK ISO 3 ERROR: PIN length must be between 4 and 12"
    );
}

#[test]
fn test_decode_pin_field_iso_3_invalid_filler() {
    let invalid_filler = hex::decode("34123456789AB123").unwrap(); // Filler contains '1' and '2'
    assert_eq!(
        decode_pin_field_iso_3(&invalid_filler)
            .unwrap_err()
            .to_string(),
        "PIN BLOCK ISO 3 ERROR: PIN block filler is incorrect"
    );
}

#[test]
fn test_decode_pin_field_iso_3_invalid_pin_digits() {
    let invalid_pin_digits = hex::decode("34ABCDFFFFFFFFFF").unwrap(); // 'A', 'B', 'C', 'D' are not numeric
    assert_eq!(
        decode_pin_field_iso_3(&invalid_pin_digits)
            .unwrap_err()
            .to_string(),
        "PIN BLOCK ISO 3 ERROR: PIN contains invalid digit"
    );
}

#[test]
fn test_encode_pan_field_iso_3_various_pans() {
    let test_cases = [
        ("1234567890123", "0000123456789012"),
        ("12345678901234", "0000234567890123"),
        ("123456789012345", "0000345678901234"),
        ("1234567890123456", "0000456789012345"),
        ("12345678901234567", "0000567890123456"),
        ("123456789012345678", "0000678901234567"),
        ("1234567890123456789", "0000789012345678"),
    ];

    for (pan, expected_hex) in test_cases {
        let encoded = encode_pan_field_iso_3(pan).unwrap();
        let encoded_hex = hex::encode(encoded);

        assert_eq!(
            encoded_hex.to_uppercase(),
            expected_hex,
            "Failed test for PAN: {}",
            pan
        );
    }
}

#[test]
fn test_encode_pan_field_iso_3_pan_too_short() {
    let short_pan = "12345678901"; // PAN length is 11, which is less than required 13

    let error = encode_pan_field_iso_3(short_pan).unwrap_err().to_string();

    assert_eq!(
        error,
        "PIN BLOCK ISO 3 ERROR: PAN must be at least 13 digits long for ISO 3 encoding"
    );
}

#[test]
fn test_encode_pinblock_iso_3_various_pins() {
    let test_cases = [
        ("1234", "12345678901234", "341217BA9876FEDC"),
        ("12345", "1234567890123", "3512266BA9876FED"),
        ("123456", "123456789012345", "36120000876FEDCB"),
        ("1234567", "1234567890123456", "37127131F6FEDCBA"),
        ("12345678", "12345678901234567", "3812622EE8EDCBA9"),
        ("12345678901", "123456789012345678", "3B1253DF79B35A98"),
        ("123456789012", "1234567890123456789", "3C124CC66AA44487"),
    ];

    let rnd_seed = vec![0xFF; 8]; // Random seed is always 0xFF, 0xFF, 0xFF, ...

    for (pin, pan, expected_hex) in test_cases {
        let pin_block = encode_pinblock_iso_3(pin, pan, rnd_seed.clone()).unwrap();
        let pin_block_hex = hex::encode_upper(pin_block);

        assert_eq!(
            pin_block_hex, expected_hex,
            "Failed test for PIN: {}, PAN: {}",
            pin, pan
        );
    }
}

#[test]
fn test_decode_pinblock_iso_3_various_pins() {
    let test_cases = [
        ("1234", "12345678901234", "341217BA9876FEDC"),
        ("12345", "1234567890123", "3512266BA9876FED"),
        ("123456", "123456789012345", "36120000876FEDCB"),
        ("1234567", "1234567890123456", "37127131F6FEDCBA"),
        ("12345678", "12345678901234567", "3812622EE8EDCBA9"),
        ("12345678901", "123456789012345678", "3B1253DF79B35A98"),
        ("123456789012", "1234567890123456789", "3C124CC66AA44487"),
    ];

    for (pin, pan, hex_pin_block) in test_cases {
        let pin_block =
            Vec::from_hex(hex_pin_block).expect("Failed to decode hex string to byte array");

        let decoded_pin =
            decode_pinblock_iso_3(&pin_block, pan).expect("Failed to decode PIN block");

        assert_eq!(
            decoded_pin, pin,
            "Decoded PIN does not match for PIN: {}, PAN: {}",
            pin, pan
        );
    }
}
