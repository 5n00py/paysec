use paysec_crypto::AesKeySize;

use paysec_crypto_rustcrypto::RustCryptoProvider;
use paysec_crypto_soft_aes::SoftAesProvider;

use paysec_dukpt::{InitialKeyId, derive_update_key};

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
fn test_derive_update_key_aes_128_annex_b() {
    for_each_crypto_provider!(provider, {
        // ANSI X9.24-3-2017 Annex B.
        let bdk = hex::decode("FEDCBA9876543210F1F1F1F1F1F1F1F1").unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let update_key = derive_update_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits128,
            initial_key_id,
        )
        .unwrap();

        assert_eq!(
            hex::encode_upper(update_key.expose_secret(),),
            "9A9770AEE1ACD1B13473D0463A1883B9",
        );
    });
}

#[test]
fn test_derive_update_key_aes_192_reference() {
    for_each_crypto_provider!(provider, {
        // Generated using the ASC X9 X9.24-3 reference algorithm.
        let bdk = hex::decode(concat!(
            "FEDCBA9876543210",
            "F1F1F1F1F1F1F1F1",
            "FEDCBA9876543210",
        ))
        .unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let update_key = derive_update_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits192,
            initial_key_id,
        )
        .unwrap();

        assert_eq!(
            hex::encode_upper(update_key.expose_secret(),),
            concat!("8222D2B5467D432E12269F5C85FF9F3F", "465528EF503A7C11",),
        );
    });
}

#[test]
fn test_derive_update_key_aes_256_x9_vectors() {
    for_each_crypto_provider!(provider, {
        // ASC X9 supplemental X9.24-3 test vectors.
        let bdk = hex::decode(concat!(
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
        ))
        .unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let update_key = derive_update_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            initial_key_id,
        )
        .unwrap();

        assert_eq!(
            hex::encode_upper(update_key.expose_secret(),),
            concat!(
                "AEFB210C136278A1279F7C8815F446DB",
                "8EBE2AA910B157AA4E6484D8DE9C4807",
            ),
        );
    });
}
