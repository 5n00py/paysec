use super::super::payload::construct_payload;

#[test]
fn test_construct_payload() {
    let key = hex::decode("AABBCCDDEEFFAABB").unwrap();
    let random_seed = hex::decode("8E3BF4CF899549351C4D467585EC0C01BCC3FCAAF9CE").unwrap();
    let masked_key_length = 16; // The minimum length for the key data
    let cipher_block_length = 16; // AES block size

    let result = construct_payload(&key, masked_key_length, cipher_block_length, &random_seed);

    assert!(result.is_ok());
    let payload = result.unwrap();

    // Expected payload: 0040 (key length in bits) + key (AABBCCDDEEFFAABB) + padding (from random seed)
    let expected_payload =
        hex::decode("0040AABBCCDDEEFFAABB8E3BF4CF899549351C4D467585EC0C01BCC3FCAAF9CE").unwrap();

    assert_eq!(payload, expected_payload);
}

#[test]
fn test_construct_payload_a7421() {
    // Test vectors from TR31:2018, A.7.4.2.1
    let key = hex::decode("3F419E1CB7079442AA37474C2EFBF8B8").unwrap();
    let random_seed = hex::decode("1C2965473CE206BB855B01533782").unwrap();
    let masked_key_length = 16; // The minimum length for the key data
    let cipher_block_length = 16; // AES block size

    let result = construct_payload(&key, masked_key_length, cipher_block_length, &random_seed);

    assert!(result.is_ok());
    let payload = result.unwrap();

    let expected_payload =
        hex::decode("00803F419E1CB7079442AA37474C2EFBF8B81C2965473CE206BB855B01533782").unwrap();

    assert_eq!(payload, expected_payload);
}
