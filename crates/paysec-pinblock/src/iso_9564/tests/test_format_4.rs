use crate::*;

use hex::decode;
use paysec_crypto_rustcrypto::RustCryptoProvider;
use paysec_crypto_soft_aes::SoftAesProvider;

macro_rules! for_each_crypto_provider {
    ($provider:ident, $body:block) => {{
        {
            let $provider = SoftAesProvider::new();
            $body
        }

        {
            let $provider = RustCryptoProvider::new();
            $body
        }
    }};
}

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
        let rnd_seed = decode(rnd_seed_hex).unwrap();
        let expected_result = decode(expected_hex).unwrap();

        let mut expected_bytes = [0u8; 16];
        expected_bytes.copy_from_slice(&expected_result);

        assert_eq!(
            encode_pin_field_iso_4(pin, rnd_seed).unwrap(),
            expected_bytes,
            "Failed test for PIN: {pin}"
        );
    }
}

#[test]
fn test_encode_pin_field_iso_4_invalid_pin_length() {
    let pin = "123";
    let rnd_seed = decode("0000000000000000").unwrap();

    assert!(encode_pin_field_iso_4(pin, rnd_seed).is_err());

    let pin = "1234567890123";
    let rnd_seed = decode("0000000000000000").unwrap();

    assert!(encode_pin_field_iso_4(pin, rnd_seed).is_err());
}

#[test]
fn test_encode_pin_field_iso_4_non_numeric_pin() {
    let pin = "12A4";
    let rnd_seed = decode("0000000000000000").unwrap();

    assert!(encode_pin_field_iso_4(pin, rnd_seed).is_err());
}

#[test]
fn test_encode_pin_field_iso_4_invalid_rnd_seed_length() {
    let pin = "1234";
    let rnd_seed = decode("00000000").unwrap();

    assert!(encode_pin_field_iso_4(pin, rnd_seed).is_err());
}

#[test]
fn test_encode_pin_field_iso_4_too_short() {
    let pin = "123";
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
    let pin = "1234567890123";
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
        let encoded_bytes = decode(encoded_hex).unwrap();

        let decoded_pin = decode_pin_field_iso_4(&encoded_bytes).unwrap();

        assert_eq!(
            decoded_pin.expose_secret(),
            expected_pin,
            "Failed test for encoded PIN field: {encoded_hex}"
        );
    }
}

#[test]
fn test_decode_pin_field_iso_4_invalid_length() {
    let pin_field = vec![0u8; 15];

    assert!(matches!(
        decode_pin_field_iso_4(&pin_field),
        Err(e)
            if e.to_string()
                == "PIN BLOCK ISO 4 ERROR: PIN field must be 16 bytes long"
    ));
}

#[test]
fn test_decode_pin_field_iso_4_invalid_control_field() {
    let mut pin_field = vec![0u8; 16];
    pin_field[0] = 0x30;

    assert!(matches!(
        decode_pin_field_iso_4(&pin_field),
        Err(e)
            if e.to_string()
                .contains("PIN block is not ISO format 4: control field")
    ));
}

#[test]
fn test_decode_pin_field_iso_4_invalid_pin_length() {
    let pin_field = vec![0x40; 16];

    assert!(matches!(
        decode_pin_field_iso_4(&pin_field),
        Err(e)
            if e.to_string()
                .contains("PIN length must be between 4 and 12")
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
        Err(e)
            if e.to_string()
                == "PIN BLOCK ISO 4 ERROR: PIN contains invalid digit"
    ));
}

#[test]
fn test_decode_pin_field_iso_4_invalid_filler() {
    let pin_field = vec![
        0x44, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    assert!(matches!(
        decode_pin_field_iso_4(&pin_field),
        Err(e)
            if e.to_string()
                == "PIN BLOCK ISO 4 ERROR: PIN block filler is incorrect"
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
        let expected_result = decode(expected_hex).unwrap();

        let mut expected_bytes = [0u8; 16];
        expected_bytes.copy_from_slice(&expected_result);

        assert_eq!(
            encode_pan_field_iso_4(pan).unwrap(),
            expected_bytes,
            "Failed test for PAN: {pan}"
        );
    }
}

#[test]
fn test_encode_pan_field_iso_4_too_short() {
    let result = encode_pan_field_iso_4("");

    assert!(result.is_err());

    assert_eq!(
        result.unwrap_err().to_string(),
        "PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long."
    );
}

#[test]
fn test_encode_pan_field_iso_4_too_long() {
    let result = encode_pan_field_iso_4("12345678901234567890");

    assert!(result.is_err());

    assert_eq!(
        result.unwrap_err().to_string(),
        "PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long."
    );
}

#[test]
fn test_encode_pan_field_iso_4_invalid_char() {
    let result = encode_pan_field_iso_4("123456789x123456789");

    assert!(result.is_err());

    assert_eq!(
        result.unwrap_err().to_string(),
        "PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long."
    );
}

#[test]
fn test_encipher_pinblock_iso_4_valid() {
    for_each_crypto_provider!(provider, {
        let key = decode("00112233445566778899AABBCCDDEEFF").expect("Invalid key hex");

        let pin = "1234";
        let pan = "1234567890123456789";

        let rnd_seed = vec![0xFF; 8];

        let expected_pin_block = "28B41FDDD29B743E93124BD8E32D921E";

        let result = encipher_pinblock_iso_4(&provider, key.as_slice(), pin, pan, rnd_seed)
            .expect("Failed to encipher PIN block");

        let result_hex = hex::encode_upper(result);

        assert_eq!(result_hex, expected_pin_block,);
    });
}

#[test]
fn test_decipher_pinblock_iso_4_various() {
    for_each_crypto_provider!(provider, {
        let key = decode("00112233445566778899AABBCCDDEEFF").expect("Invalid key hex");

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
            let encrypted_pin_block = decode(encrypted_pin_block_hex).unwrap();

            let decrypted_pin =
                decipher_pinblock_iso_4(&provider, key.as_slice(), &encrypted_pin_block, pan)
                    .expect("Failed to decipher PIN block");

            assert_eq!(
                decrypted_pin.expose_secret(),
                expected_pin,
                "Deciphered PIN does not match expected PIN"
            );
        }
    });
}
