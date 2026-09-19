use cms::cert::IssuerAndSerialNumber;
use cms::enveloped_data::EnvelopedData;

use der::{Any, Decode, Encode};

use paysec_tr34::{KdhCredential, KdhCrl, KrdCredential};

use x509_cert::Certificate;

use paysec_crypto::{AesBlockCipher, AesCbc};

use paysec_crypto_rustcrypto::RustCryptoProvider;

const KDH_1_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/tr34-2019/kdh-1-certificate.der");

const KRD_1_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/tr34-2019/krd-1-certificate.der");

const CA_KDH_CRL_DER: &[u8] = include_bytes!("fixtures/tr34-2019/ca-kdh.crl.der");

const AES_KEY_BLOCK_DER: &[u8] = include_bytes!("fixtures/tr34-2019/aes-key-block.der");

const AES_ENVELOPED_DATA_DER: &[u8] = include_bytes!("fixtures/tr34-2019/aes-enveloped-data.der");

const AES_BLOCK_SIZE: usize = 16;

fn official_aes_ephemeral_key() -> [u8; AES_BLOCK_SIZE] {
    hex::decode("0123456789ABCDEFFEDCBA9876543210")
        .unwrap()
        .try_into()
        .unwrap()
}

fn official_aes_ciphertext() -> Vec<u8> {
    hex::decode(concat!(
        "0DDE931D281DEB8BCCAAF801944DF5A8",
        "B3D6056B67B3B5E64319DB02986E5D2A",
        "3BA7871D509F8EC36C269A3EF93C53C0",
        "A87538DB781C2D0DC0A67D4E5A6797E9",
        "676B94CD6F63E610418B743797FD37DC",
        "AA45FB89CCA7507A38751E02EABF4321",
        "43B9A60630F453C2E736FECDD49F4E62",
        "63F6294D408C1AD4A755B697E752458F",
        "7C17103B420A4BB52B9CDEA8687D2784",
    ))
    .unwrap()
}

fn recover_official_aes_iv() -> [u8; AES_BLOCK_SIZE] {
    let provider = RustCryptoProvider::new();

    let key = official_aes_ephemeral_key();

    let first_ciphertext_block: [u8; AES_BLOCK_SIZE] = official_aes_ciphertext()[..AES_BLOCK_SIZE]
        .try_into()
        .unwrap();

    // B.2.2.3.2 encrypts an Annex-B-style KeyBlock. Its first block is
    // identical to the independently published AES KeyBlock in B.2.2.2.4,
    // so CBC gives us:
    //
    //     IV = AES^-1_K(C1) XOR P1
    //
    // This lets us recover the actual 16-byte IV used to produce the
    // published ciphertext despite Annex B serializing only eight bytes.
    let decrypted_first_block = provider
        .decrypt_block(key.as_slice(), &first_ciphertext_block)
        .unwrap();

    let first_plaintext_block = &AES_KEY_BLOCK_DER[..AES_BLOCK_SIZE];

    let mut iv = [0u8; AES_BLOCK_SIZE];

    for index in 0..AES_BLOCK_SIZE {
        iv[index] = decrypted_first_block[index] ^ first_plaintext_block[index];
    }

    iv
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn parses_official_tr34_2019_credentials_and_crl() {
    KdhCredential::from_der(KDH_1_CERTIFICATE_DER).unwrap();

    KrdCredential::from_der(KRD_1_CERTIFICATE_DER).unwrap();

    KdhCrl::from_der(CA_KDH_CRL_DER).unwrap();
}

#[test]
fn official_aes_enveloped_data_is_preserved_as_published_der() {
    // The Annex B sample is syntactically valid DER, even though its
    // EncryptedContentInfo does not conform to the CMS schema expected by
    // the strict `cms::EnvelopedData` decoder.
    let value = Any::from_der(AES_ENVELOPED_DATA_DER).unwrap();

    assert_eq!(value.to_der().unwrap(), AES_ENVELOPED_DATA_DER,);
}

#[test]
fn official_aes_enveloped_data_requires_compatibility_parsing() {
    // Annex B.2.2.3.2 places encryptedContent inside the SEQUENCE used for
    // contentEncryptionAlgorithm rather than as its EncryptedContentInfo
    // sibling.
    //
    // Keep this expected rejection until an explicit Annex B compatibility
    // decoder/profile exists.
    assert!(EnvelopedData::from_der(AES_ENVELOPED_DATA_DER,).is_err());
}

#[test]
fn official_aes_sample_records_expected_recipient_and_oaep_encoding() {
    let krd_certificate = Certificate::from_der(KRD_1_CERTIFICATE_DER).unwrap();

    let recipient_identifier = IssuerAndSerialNumber {
        issuer: krd_certificate.tbs_certificate.issuer.clone(),

        serial_number: krd_certificate.tbs_certificate.serial_number.clone(),
    }
    .to_der()
    .unwrap();

    assert!(
        find_subslice(AES_ENVELOPED_DATA_DER, &recipient_identifier,).is_some(),
        "official AES sample does not contain the expected KRD issuer and serial number",
    );

    // Exact AlgorithmIdentifier bytes published by Annex B.2.2.3.2.
    //
    // Keep the sample encoding byte-for-byte here. Its OAEP parameter
    // representation is itself compatibility material and should not be
    // normalized into the strict PKCS#1 representation by this test.
    let published_oaep_algorithm = hex::decode(concat!(
        "3045",
        "06092A864886F70D010107",
        "3038",
        "300D06096086480165030402010500",
        "301806092A864886F70D010108",
        "300B0609608648016503040201",
        "300D06092A864886F70D0101090400",
    ))
    .unwrap();

    assert!(
        find_subslice(AES_ENVELOPED_DATA_DER, &published_oaep_algorithm,).is_some(),
        "official AES sample does not contain the published RSAES-OAEP encoding",
    );
}

#[test]
fn official_aes_sample_records_published_iv_and_ciphertext() {
    let aes_oid = hex::decode("0609608648016503040102").unwrap();

    let aes_oid_offset = find_subslice(AES_ENVELOPED_DATA_DER, &aes_oid)
        .expect("AES-128-CBC OID not found in official sample");

    // Annex B encodes the contentEncryptionAlgorithm as:
    //
    //   SEQUENCE (length 168)
    //       AES-128-CBC OID
    //       OCTET STRING (8-byte IV)
    //       [0] encryptedContent
    //
    // The final element belongs to EncryptedContentInfo, not inside the
    // AlgorithmIdentifier. This malformed nesting is why the strict CMS
    // decoder rejects the published sample.
    assert_eq!(
        &AES_ENVELOPED_DATA_DER[aes_oid_offset - 3..aes_oid_offset],
        &[0x30, 0x81, 0xA8],
    );

    assert_eq!(
        &AES_ENVELOPED_DATA_DER[aes_oid_offset..aes_oid_offset + aes_oid.len()],
        aes_oid.as_slice(),
    );

    let iv_offset = aes_oid_offset + aes_oid.len();

    let published_iv = hex::decode("04080123456789ABCDEF").unwrap();

    assert_eq!(
        &AES_ENVELOPED_DATA_DER[iv_offset..iv_offset + published_iv.len()],
        published_iv.as_slice(),
    );

    // The official sample uses an 8-byte IV parameter even though the
    // strict AES-CBC path implemented by paysec-tr34 uses a 16-byte IV.
    let encrypted_content_offset = iv_offset + published_iv.len();

    assert_eq!(
        &AES_ENVELOPED_DATA_DER[encrypted_content_offset..encrypted_content_offset + 3],
        &[0x80, 0x81, 0x90],
    );

    let expected_ciphertext = hex::decode(concat!(
        "0DDE931D281DEB8BCCAAF801944DF5A8",
        "B3D6056B67B3B5E64319DB02986E5D2A",
        "3BA7871D509F8EC36C269A3EF93C53C0",
        "A87538DB781C2D0DC0A67D4E5A6797E9",
        "676B94CD6F63E610418B743797FD37DC",
        "AA45FB89CCA7507A38751E02EABF4321",
        "43B9A60630F453C2E736FECDD49F4E62",
        "63F6294D408C1AD4A755B697E752458F",
        "7C17103B420A4BB52B9CDEA8687D2784",
    ))
    .unwrap();

    let ciphertext_offset = encrypted_content_offset + 3;

    assert_eq!(
        &AES_ENVELOPED_DATA_DER[ciphertext_offset..],
        expected_ciphertext.as_slice(),
    );

    assert_eq!(expected_ciphertext.len(), 144,);
}

#[test]
fn official_aes_key_block_fixture_is_preserved_for_compatibility_work() {
    // Annex B.2.2.2.4 is deliberately retained byte-for-byte even though
    // its encoding differs from the strict Annex D KeyBlock representation
    // implemented by paysec-tr34.
    assert_eq!(AES_KEY_BLOCK_DER.len(), 133,);

    // Published sample version is INTEGER 1.
    assert_eq!(
        &AES_KEY_BLOCK_DER[..6],
        &[0x30, 0x81, 0x82, 0x02, 0x01, 0x01,],
    );

    // Published AES sample KBH.
    assert!(find_subslice(AES_KEY_BLOCK_DER, b"D0256K0AB00E0000",).is_some(),);
}

#[test]
fn recovers_official_aes_iv_from_first_cbc_block() {
    let recovered_iv = recover_official_aes_iv();

    let expected_iv: [u8; AES_BLOCK_SIZE] = hex::decode("0123456789ABCDEF0000000000000000")
        .unwrap()
        .try_into()
        .unwrap();

    assert_eq!(recovered_iv, expected_iv,);
}

#[test]
fn decrypts_official_aes_ciphertext_with_recovered_iv() {
    let provider = RustCryptoProvider::new();

    let key = official_aes_ephemeral_key();

    let iv = recover_official_aes_iv();

    let plaintext = provider
        .decrypt_cbc(key.as_slice(), &iv, &official_aes_ciphertext())
        .unwrap();

    assert_eq!(plaintext.len(), 144,);

    // The beginning of the decrypted object agrees with the independently
    // published Annex B.2.2.2.4 AES KeyBlock. The divergence occurs later
    // in the KBH value.
    assert_eq!(&plaintext[..100], &AES_KEY_BLOCK_DER[..100],);
}

#[test]
fn decrypted_official_aes_key_block_has_valid_padding() {
    let provider = RustCryptoProvider::new();

    let key = official_aes_ephemeral_key();

    let iv = recover_official_aes_iv();

    let plaintext = provider
        .decrypt_cbc(key.as_slice(), &iv, &official_aes_ciphertext())
        .unwrap();

    // The decrypted KeyBlock is 133 bytes. AES-CBC therefore has eleven
    // bytes of CMS/PKCS#7 padding, each containing 0x0B.
    let padding_length = *plaintext.last().unwrap() as usize;

    assert_eq!(padding_length, 11,);

    assert_eq!(&plaintext[plaintext.len() - padding_length..], &[0x0B; 11],);

    assert_eq!(plaintext.len() - padding_length, 133,);
}

#[test]
fn decrypted_official_aes_key_block_uses_a0256_header() {
    let provider = RustCryptoProvider::new();

    let key = official_aes_ephemeral_key();

    let iv = recover_official_aes_iv();

    let padded_plaintext = provider
        .decrypt_cbc(key.as_slice(), &iv, &official_aes_ciphertext())
        .unwrap();

    let padding_length = *padded_plaintext.last().unwrap() as usize;

    let key_block = &padded_plaintext[..padded_plaintext.len() - padding_length];

    assert_eq!(key_block.len(), 133,);

    // B.2.2.3.2 was not produced from the separately published AES
    // KeyBlock in B.2.2.2.4. Its decrypted plaintext instead contains
    // the TDEA-style sample KBH used elsewhere in Annex B.
    assert!(find_subslice(key_block, b"A0256K0TB00E0000",).is_some(),);

    assert!(find_subslice(key_block, b"D0256K0AB00E0000",).is_none(),);

    assert_ne!(key_block, AES_KEY_BLOCK_DER,);
}
