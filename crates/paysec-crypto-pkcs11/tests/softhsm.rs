use std::env;

use paysec_crypto::AesBlockCipher;
use paysec_crypto_pkcs11::{Pkcs11Auth, Pkcs11Config, Pkcs11Key, Pkcs11Provider, TokenSelector};

const AES_KEY_ID: [u8; 1] = [0x10];
const AES_KEY_LABEL: &str = "paysec-aes-128";

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
