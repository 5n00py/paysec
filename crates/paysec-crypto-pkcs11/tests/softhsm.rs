use std::env;

use paysec_crypto::{
    AesBlockCipher, AesCbc, AesCmac, RsaPkcs1v15Sha256Sign, RsaPkcs1v15Sha256Verify,
};
use paysec_crypto_pkcs11::{Pkcs11Auth, Pkcs11Config, Pkcs11Key, Pkcs11Provider, TokenSelector};

const AES_KEY_ID: [u8; 1] = [0x10];
const AES_KEY_LABEL: &str = "paysec-aes-128";
const AES_NIST_KEY_ID: [u8; 1] = [0x11];
const RSA_KEY_ID: [u8; 1] = [0x20];

fn provider_from_env() -> Pkcs11Provider {
    let module_path = env::var("PAYSEC_PKCS11_MODULE").expect("PAYSEC_PKCS11_MODULE must be set");

    let token_label =
        env::var("PAYSEC_PKCS11_TOKEN_LABEL").expect("PAYSEC_PKCS11_TOKEN_LABEL must be set");

    let user_pin = env::var("PAYSEC_PKCS11_USER_PIN").expect("PAYSEC_PKCS11_USER_PIN must be set");

    let config = Pkcs11Config::new(module_path, TokenSelector::label(token_label));

    let auth = Pkcs11Auth::user_pin(user_pin);

    Pkcs11Provider::connect(&config, &auth).expect("failed to connect to SoftHSM test token")
}

#[test]
#[ignore = "requires a provisioned SoftHSM token; see tests/README.md"]
fn aes_block_cipher_matches_known_answer_vector() {
    let provider = provider_from_env();

    let plaintext = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    let ciphertext = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];

    let key_by_id = Pkcs11Key::by_id(AES_KEY_ID);

    let encrypted = provider
        .encrypt_block(&key_by_id, &plaintext)
        .expect("AES block encryption failed");

    assert_eq!(encrypted, ciphertext);

    // Resolve the same provisioned object using its label as well.
    let key_by_label = Pkcs11Key::by_label(AES_KEY_LABEL);

    let decrypted = provider
        .decrypt_block(&key_by_label, &ciphertext)
        .expect("AES block decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[test]
#[ignore = "requires a provisioned SoftHSM token; see tests/README.md"]
fn aes_cbc_matches_known_answer_vector() {
    let provider = provider_from_env();

    let key = Pkcs11Key::by_id(AES_NIST_KEY_ID);

    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let plaintext = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];

    let expected = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19,
        0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
        0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22,
        0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30,
        0x75, 0x86, 0xe1, 0xa7,
    ];

    let encrypted = provider
        .encrypt_cbc(&key, &iv, &plaintext)
        .expect("AES-CBC encryption failed");

    assert_eq!(encrypted, expected);

    let decrypted = provider
        .decrypt_cbc(&key, &iv, &expected)
        .expect("AES-CBC decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[test]
#[ignore = "requires a provisioned SoftHSM token; see tests/README.md"]
fn aes_cmac_matches_rfc_4493_known_answer_vector() {
    let provider = provider_from_env();

    let key = Pkcs11Key::by_id(AES_NIST_KEY_ID);

    let message = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];

    let expected = [
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28,
        0x7c,
    ];

    let mac = provider
        .calculate_cmac(&key, &message)
        .expect("AES-CMAC calculation failed");

    assert_eq!(mac, expected);
}

#[test]
#[ignore = "requires a provisioned SoftHSM token; see tests/README.md"]
fn missing_aes_key_returns_error() {
    let provider = provider_from_env();

    let key = Pkcs11Key::by_id([0xff]);
    let block = [0u8; 16];

    let error = provider
        .encrypt_block(&key, &block)
        .expect_err("missing key must fail");

    assert!(error.to_string().contains("no matching PKCS #11 key found"));
}

#[test]
#[ignore = "requires a provisioned SoftHSM token; see tests/README.md"]
fn aes_cbc_rejects_non_block_aligned_input() {
    let provider = provider_from_env();

    let key = Pkcs11Key::by_id(AES_NIST_KEY_ID);
    let iv = [0u8; 16];
    let plaintext = [0u8; 15];

    let error = provider
        .encrypt_cbc(&key, &iv, &plaintext)
        .expect_err("non-block-aligned plaintext must fail");

    assert_eq!(
        error.to_string(),
        "AES-CBC plaintext length must be a multiple of 16 bytes"
    );
}

#[test]
#[ignore = "requires a provisioned SoftHSM token; see tests/README.md"]
fn rsa_pkcs1v15_sha256_sign_and_verify() {
    let provider = provider_from_env();

    let key = Pkcs11Key::by_id(RSA_KEY_ID);
    let message = b"TR-34 test message";

    let signature = provider
        .sign_pkcs1v15_sha256(&key, message)
        .expect("RSA-PKCS1-v1_5-SHA256 signing failed");

    // RSA-2048 signatures are exactly 256 bytes.
    assert_eq!(signature.len(), 256);

    provider
        .verify_pkcs1v15_sha256(&key, message, &signature)
        .expect("RSA-PKCS1-v1_5-SHA256 verification failed");
}

#[test]
#[ignore = "requires a provisioned SoftHSM token; see tests/README.md"]
fn rsa_pkcs1v15_sha256_rejects_modified_message() {
    let provider = provider_from_env();

    let key = Pkcs11Key::by_id(RSA_KEY_ID);

    let signature = provider
        .sign_pkcs1v15_sha256(&key, b"original message")
        .expect("RSA-PKCS1-v1_5-SHA256 signing failed");

    let result = provider.verify_pkcs1v15_sha256(&key, b"modified message", &signature);

    assert!(result.is_err());
}
