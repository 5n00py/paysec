use paysec_crypto::AesKeySize;

use paysec_crypto_rustcrypto::RustCryptoProvider;
use paysec_crypto_soft_aes::SoftAesProvider;

use paysec_dukpt::{InitialKeyId, derive_initial_key};

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
fn test_derive_initial_key_aes_128() {
    for_each_crypto_provider!(provider, {
        // ANSI X9.24-3-2017 Annex B
        let bdk = hex::decode("FEDCBA9876543210F1F1F1F1F1F1F1F1").unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let initial_key = derive_initial_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits128,
            initial_key_id,
        )
        .unwrap();

        let expected_initial_key = hex::decode("1273671EA26AC29AFA4D1084127652A1").unwrap();

        assert_eq!(initial_key.expose_secret(), expected_initial_key.as_slice(),);
    });
}

#[test]
fn test_dukpt_key_debug_is_redacted() {
    let key = paysec_dukpt::DukptKey::from_slice(&[0xAA; 16]);

    assert_eq!(format!("{key:?}"), "DukptKey([REDACTED])",);
}

#[test]
fn test_derive_initial_key_aes_256() {
    for_each_crypto_provider!(provider, {
        let bdk = hex::decode(concat!(
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
        ))
        .unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let initial_key = derive_initial_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            initial_key_id,
        )
        .unwrap();

        let expected_initial_key = hex::decode(concat!(
            "CE9CE0C101D1138F97FB6CAD4DF045A7",
            "083D4EAE2D35A31789D01CCF0949550F",
        ))
        .unwrap();

        assert_eq!(initial_key.expose_secret(), expected_initial_key.as_slice(),);
    });
}

#[test]
fn test_derive_initial_key_aes_192() {
    for_each_crypto_provider!(provider, {
        // Generated from the ASC X9 reference algorithm using the
        // AES-192 BDK defined in the reference Python source.
        let bdk = hex::decode(concat!(
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
            "FEDCBA9876543210",
        ))
        .unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let initial_key = derive_initial_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits192,
            initial_key_id,
        )
        .unwrap();

        let expected_initial_key = hex::decode(concat!(
            "5B6DEE2B5B7FABFFA32591F35BF8F23D",
            "D9329AE85131E584",
        ))
        .unwrap();

        assert_eq!(initial_key.expose_secret(), expected_initial_key.as_slice(),);
    });
}
