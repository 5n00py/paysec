use paysec_crypto::AesKeySize;

use paysec_crypto_rustcrypto::RustCryptoProvider;
use paysec_crypto_soft_aes::SoftAesProvider;

use paysec_dukpt::{DukptError, InitialKeyId, WorkingKeyUsage, derive_working_key};

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

struct WorkingKeyVector {
    counter: u32,
    pin: &'static str,
    mac_generation: &'static str,
    data_encryption: &'static str,
}

const AES_128_VECTORS: &[WorkingKeyVector] = &[
    WorkingKeyVector {
        counter: 0x0000_0001,
        pin: "AF8CB133A78F8DC2D1359F18527593FB",
        mac_generation: "A2DC23DE6FDE0824A2BC321E08E4B8B7",
        data_encryption: "A35C412EFD41FDB98B69797C02DCD08F",
    },
    WorkingKeyVector {
        counter: 0x0000_0002,
        pin: "D30BDC73EC9714B000BEC66BDB7B6D09",
        mac_generation: "484C3B06E8562704528CD5B46FB12FB6",
        data_encryption: "D639514AA33AC43AD9229E433D6D4E5B",
    },
    WorkingKeyVector {
        counter: 0x0000_0003,
        pin: "7D69F01F3B45449F62C7816ECE723268",
        mac_generation: "A5DF7D9D800CA769766F0C77CA4E6E6C",
        data_encryption: "EF17F6AB45B4820C93A3DCB21BC491AD",
    },
    WorkingKeyVector {
        counter: 0x0000_0004,
        pin: "91A0588318EC2673214271F70137896E",
        mac_generation: "E6E4679647D8A9057C1FC15537CB4C4E",
        data_encryption: "B3BD44C08BB6BA27C3BB4711D7D70387",
    },
    WorkingKeyVector {
        counter: 0x0000_0005,
        pin: "35A43BC9EFEB09C756204B57E3FB7D4D",
        mac_generation: "0588185FE1FF8C7E22FAD78C1C61F065",
        data_encryption: "CA02DF6F30B39E14BD0B4A30E460920F",
    },
    WorkingKeyVector {
        counter: 0x0001_FFFE,
        pin: "DDF7E08A84B5478C498D007C743BF762",
        mac_generation: "6D7623AD652734B8FAE1B6E093EACE3D",
        data_encryption: "8E4E5D5E0F01C54F01F4ACA1C8F8EDCE",
    },
    WorkingKeyVector {
        counter: 0x0001_FFFF,
        pin: "73BA667D6368A2086E72576DF41A4037",
        mac_generation: "8B543DCF4A31EA3AB47DAD16B8ABD404",
        data_encryption: "D18ACA30B4D63DB61CE474D3F57733D3",
    },
    WorkingKeyVector {
        counter: 0x0002_0000,
        pin: "AB828BE7B58C7EC5D5ED0D5D320A0C9D",
        mac_generation: "0B59D3D7D93028D97135FB895CACE24E",
        data_encryption: "13361208975755318FE7AE28C9616014",
    },
];

fn assert_working_key<P>(
    provider: &P,
    bdk: &[u8],
    derivation_key_size: AesKeySize,
    working_key_size: AesKeySize,
    initial_key_id: InitialKeyId,
    counter: u32,
    usage: WorkingKeyUsage,
    expected: &str,
) where
    P: paysec_crypto::AesBlockCipher<[u8]>,
{
    let key = derive_working_key(
        provider,
        bdk,
        derivation_key_size,
        usage,
        working_key_size,
        initial_key_id,
        counter,
    )
    .unwrap();

    assert_eq!(
        hex::encode_upper(key.expose_secret(),),
        expected,
        "working key mismatch for counter {counter:#010X}",
    );
}

#[test]
fn test_derive_working_keys_aes_128_annex_b() {
    for_each_crypto_provider!(provider, {
        let bdk = hex::decode("FEDCBA9876543210F1F1F1F1F1F1F1F1").unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        for vector in AES_128_VECTORS {
            assert_working_key(
                &provider,
                bdk.as_slice(),
                AesKeySize::Bits128,
                AesKeySize::Bits128,
                initial_key_id,
                vector.counter,
                WorkingKeyUsage::PinEncryption,
                vector.pin,
            );

            assert_working_key(
                &provider,
                bdk.as_slice(),
                AesKeySize::Bits128,
                AesKeySize::Bits128,
                initial_key_id,
                vector.counter,
                WorkingKeyUsage::MessageAuthenticationGeneration,
                vector.mac_generation,
            );

            assert_working_key(
                &provider,
                bdk.as_slice(),
                AesKeySize::Bits128,
                AesKeySize::Bits128,
                initial_key_id,
                vector.counter,
                WorkingKeyUsage::DataEncryptionEncrypt,
                vector.data_encryption,
            );
        }
    });
}

#[test]
fn test_reject_working_key_stronger_than_derivation_key() {
    for_each_crypto_provider!(provider, {
        let bdk = hex::decode("FEDCBA9876543210F1F1F1F1F1F1F1F1").unwrap();

        let result = derive_working_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits128,
            WorkingKeyUsage::PinEncryption,
            AesKeySize::Bits256,
            InitialKeyId::from_parts(0x12345678, 0x90123456),
            1,
        );

        assert!(matches!(
            result,
            Err(DukptError::WorkingKeyTooStrong {
                derivation_key_size: AesKeySize::Bits128,
                working_key_size: AesKeySize::Bits256,
            })
        ));
    });
}

#[test]
fn test_all_working_key_usages_aes_128_counter_1() {
    for_each_crypto_provider!(provider, {
        let bdk = hex::decode("FEDCBA9876543210F1F1F1F1F1F1F1F1").unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let vectors = [
            (
                WorkingKeyUsage::KeyEncryption,
                "36A724B7BEFA5A25F5E7B5782A4554A2",
            ),
            (
                WorkingKeyUsage::PinEncryption,
                "AF8CB133A78F8DC2D1359F18527593FB",
            ),
            (
                WorkingKeyUsage::MessageAuthenticationGeneration,
                "A2DC23DE6FDE0824A2BC321E08E4B8B7",
            ),
            (
                WorkingKeyUsage::MessageAuthenticationVerification,
                "DBB463945B286C07CD3AD82EE96FD9C9",
            ),
            (
                WorkingKeyUsage::MessageAuthenticationBothWays,
                "85675439D18D7F1158BD8E3EAA3D502B",
            ),
            (
                WorkingKeyUsage::DataEncryptionEncrypt,
                "A35C412EFD41FDB98B69797C02DCD08F",
            ),
            (
                WorkingKeyUsage::DataEncryptionDecrypt,
                "16292C6EA8F64C5420A0584BFBC577BE",
            ),
            (
                WorkingKeyUsage::DataEncryptionBothWays,
                "A308E080DD15A1B741F1721BF67DE11C",
            ),
            (
                WorkingKeyUsage::KeyDerivation,
                "30E54D3C69B22501A7FC43969D81D5C0",
            ),
        ];

        for (usage, expected) in vectors {
            assert_working_key(
                &provider,
                bdk.as_slice(),
                AesKeySize::Bits128,
                AesKeySize::Bits128,
                initial_key_id,
                0x0000_0001,
                usage,
                expected,
            );
        }
    });
}

#[test]
fn test_derive_aes_128_working_keys_from_aes_256_bdk() {
    for_each_crypto_provider!(provider, {
        // ASC X9 supplemental X9.24-3 test vectors.
        let bdk = hex::decode(concat!(
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
        ))
        .unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        assert_working_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            AesKeySize::Bits128,
            initial_key_id,
            1,
            WorkingKeyUsage::PinEncryption,
            "09C9C432966811D6B2C3336BAC1B1202",
        );

        assert_working_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            AesKeySize::Bits128,
            initial_key_id,
            1,
            WorkingKeyUsage::MessageAuthenticationGeneration,
            "F04A1FABD4176E15490CEC82E217A96D",
        );

        assert_working_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            AesKeySize::Bits128,
            initial_key_id,
            1,
            WorkingKeyUsage::DataEncryptionEncrypt,
            "616D59AE91F8CC7016F89FDA29605FA4",
        );
    });
}

#[test]
fn test_derive_aes_256_working_keys_from_aes_256_bdk() {
    for_each_crypto_provider!(provider, {
        let bdk = hex::decode(concat!(
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
            "FEDCBA9876543210F1F1F1F1F1F1F1F1",
        ))
        .unwrap();

        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        assert_working_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            AesKeySize::Bits256,
            initial_key_id,
            1,
            WorkingKeyUsage::PinEncryption,
            concat!(
                "8C1AB7BEE973829E30242E0BBBDD4946",
                "D540C98FC1B5BDCF94790001A23FD502",
            ),
        );

        assert_working_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            AesKeySize::Bits256,
            initial_key_id,
            1,
            WorkingKeyUsage::MessageAuthenticationGeneration,
            concat!(
                "61DABDF4B340CF461EE860B1D1AB5535",
                "7142BD2D6977306859CF49AEFE8F1549",
            ),
        );

        assert_working_key(
            &provider,
            bdk.as_slice(),
            AesKeySize::Bits256,
            AesKeySize::Bits256,
            initial_key_id,
            1,
            WorkingKeyUsage::DataEncryptionEncrypt,
            concat!(
                "71EB36C9A6B7F801D1D1700C29741FC5",
                "A5C4E9B45D742DA7AF6992B8AA29AF58",
            ),
        );
    });
}

const AES_192_TO_AES_128_VECTORS: &[WorkingKeyVector] = &[
    WorkingKeyVector {
        counter: 0x0000_0001,
        pin: "3C318CDBF08322279557201E98DBB3F3",
        mac_generation: "3E7009C74E8166BC9059D3D92D36B487",
        data_encryption: "04C5C3926A8B9B2B833F33D4C6E581EE",
    },
    WorkingKeyVector {
        counter: 0x0000_0003,
        pin: "6DE9A0A37D6927280B7E223C4BE7580F",
        mac_generation: "D2D13AF44E71EB6E8539FFDA3C37A5D6",
        data_encryption: "FDCB88BEA1EFE48EAEE83A48513FF515",
    },
    WorkingKeyVector {
        counter: 0x0001_FFFF,
        pin: "0B6B9118E99155DA668632A1940A42AD",
        mac_generation: "EC3B5AC38B7E678B6A45D4F10554934B",
        data_encryption: "35D05CE06C113EC3CFDBD1BB4E1E3CFE",
    },
];

const AES_192_TO_AES_192_VECTORS: &[WorkingKeyVector] = &[
    WorkingKeyVector {
        counter: 0x0000_0001,
        pin: "C5043EDC7F2C001097974D40FF82A050B64A1AB27879F3DB",
        mac_generation: "7FB32FB0F68F0E4A2594765F9EB1C472727EE305A5EE35E1",
        data_encryption: "C1D4541AE0E33949DD03F2A10B5E5486BBCAC1C520320E0C",
    },
    WorkingKeyVector {
        counter: 0x0000_0003,
        pin: "64AE12F5E0FB2001B22520CED9C5CF1A8AA45AAA3F264882",
        mac_generation: "29A29A9C943EAA03D2F5CAD146BA765094C2CF0343C53D1A",
        data_encryption: "A5DDCE36A4ECC8781C466C2270BA499EC4654AA166392EFC",
    },
    WorkingKeyVector {
        counter: 0x0001_FFFF,
        pin: "2ED63AC853F1DE1C510A66B165BA33D6DDC744C282F9D420",
        mac_generation: "7ACC4BDAB69C6BA729B9534292DD1E484F361C41C7B0C153",
        data_encryption: "92E250B33BC93E9BF213EA343AD7465758EEB67569C9ED90",
    },
];

fn assert_aes_192_vectors<P>(
    provider: &P,
    working_key_size: AesKeySize,
    vectors: &[WorkingKeyVector],
) where
    P: paysec_crypto::AesBlockCipher<[u8]>,
{
    let bdk = hex::decode(concat!(
        "FEDCBA9876543210",
        "F1F1F1F1F1F1F1F1",
        "FEDCBA9876543210",
    ))
    .unwrap();

    let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

    for vector in vectors {
        assert_working_key(
            provider,
            bdk.as_slice(),
            AesKeySize::Bits192,
            working_key_size,
            initial_key_id,
            vector.counter,
            WorkingKeyUsage::PinEncryption,
            vector.pin,
        );

        assert_working_key(
            provider,
            bdk.as_slice(),
            AesKeySize::Bits192,
            working_key_size,
            initial_key_id,
            vector.counter,
            WorkingKeyUsage::MessageAuthenticationGeneration,
            vector.mac_generation,
        );

        assert_working_key(
            provider,
            bdk.as_slice(),
            AesKeySize::Bits192,
            working_key_size,
            initial_key_id,
            vector.counter,
            WorkingKeyUsage::DataEncryptionEncrypt,
            vector.data_encryption,
        );
    }
}

#[test]
fn test_derive_aes_128_working_keys_from_aes_192_bdk() {
    for_each_crypto_provider!(provider, {
        // Generated using the ASC X9 X9.24-3 reference algorithm.
        assert_aes_192_vectors(&provider, AesKeySize::Bits128, AES_192_TO_AES_128_VECTORS);
    });
}

#[test]
fn test_derive_aes_192_working_keys_from_aes_192_bdk() {
    for_each_crypto_provider!(provider, {
        // Generated using the ASC X9 X9.24-3 reference algorithm.
        assert_aes_192_vectors(&provider, AesKeySize::Bits192, AES_192_TO_AES_192_VECTORS);
    });
}
