use cms::content_info::ContentInfo;

use der::{Decode, Encode};

use paysec_crypto::AesCbc;

use paysec_crypto_rustcrypto::{RsaPrivateKey, RsaPublicKey, RustCryptoProvider};

use paysec_tr34::{
    KdhCredential, KdhCrl, KrdCredential, Tr34Profile, TwoPassKeyExportRequest, export_key_two_pass,
};

use rand_core::{CryptoRng, Error as RandError, RngCore};

use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/kdh-certificate.der");

const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/krd-certificate.der");

const KDH_PRIVATE_KEY_DER: &[u8] = include_bytes!("fixtures/kdh-private-key.der");

const KDH_CRL_DER: &[u8] = include_bytes!("fixtures/kdh-crl.der");

const AES_BLOCK_SIZE: usize = 16;

struct FixedRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl FixedRng {
    fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            offset: 0,
        }
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];

        self.fill_bytes(&mut bytes);

        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];

        self.fill_bytes(&mut bytes);

        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.offset + dest.len();

        assert!(end <= self.bytes.len(), "fixed RNG exhausted");

        dest.copy_from_slice(&self.bytes[self.offset..end]);

        self.offset = end;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);

        Ok(())
    }
}

impl CryptoRng for FixedRng {}

fn deterministic_rng() -> FixedRng {
    let ephemeral_key = hex::decode("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0").unwrap();

    let iv = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();

    // RSAES-OAEP-SHA256 consumes a 32-byte random seed.
    let oaep_seed = vec![0xA5; 32];

    let mut bytes = Vec::with_capacity(64);

    bytes.extend_from_slice(&ephemeral_key);
    bytes.extend_from_slice(&iv);
    bytes.extend_from_slice(&oaep_seed);

    FixedRng::new(bytes)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn exports_two_pass_key_token_with_annex_b_2019_profile() {
    let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

    let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

    let kdh_crl = KdhCrl::from_der(KDH_CRL_DER).unwrap();

    let krd_public_key = {
        let spki = krd_credential.subject_public_key_info_der().unwrap();

        RsaPublicKey::from_public_key_der(&spki).unwrap()
    };

    let kdh_private_key = RsaPrivateKey::from_pkcs8_der(KDH_PRIVATE_KEY_DER).unwrap();

    let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

    let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

    let key_block_header = b"A0256K0TB00E0000";

    let request = TwoPassKeyExportRequest::new(
        &kdh_credential,
        &krd_credential,
        &clear_key,
        key_block_header,
        &random_nonce,
        &kdh_crl,
    )
    .with_profile(Tr34Profile::AnnexB2019);

    let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

    let token =
        export_key_two_pass(&mut provider, request, &krd_public_key, &kdh_private_key).unwrap();

    // The public API still emits a normal top-level CMS ContentInfo.
    let content_info = ContentInfo::from_der(&token).unwrap();

    assert_eq!(
        content_info.content_type.to_string(),
        "1.2.840.113549.1.7.2",
    );

    let signed_data_der = content_info.content.to_der().unwrap();

    // The Annex B compatibility profile encodes the outer
    // SignedData version as INTEGER 1.
    //
    // `content` is the SEQUENCE contents of SignedData, so the first
    // child is the version.
    assert!(
        content_info
            .content
            .value()
            .starts_with(&[0x02, 0x01, 0x01],),
    );

    // Exact RSAES-OAEP AlgorithmIdentifier representation used by
    // the Annex B compatibility profile.
    let annex_b_oaep = hex::decode(concat!(
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
        find_subslice(&signed_data_der, &annex_b_oaep,).is_some(),
        "Annex B RSAES-OAEP encoding not found",
    );

    // Annex B nests encryptedContent inside the content-encryption
    // SEQUENCE. Unlike the defective published AES vector, the
    // compatibility profile deliberately retains the full 16-byte
    // AES-CBC IV.
    let encrypted_content_prefix = hex::decode(concat!(
        "3081B0",
        "0609608648016503040102",
        "0410",
        "000102030405060708090A0B0C0D0E0F",
        "808190",
    ))
    .unwrap();

    let encrypted_content_offset = find_subslice(&signed_data_der, &encrypted_content_prefix)
        .expect("Annex B encrypted-content layout not found");

    let ciphertext_offset = encrypted_content_offset + encrypted_content_prefix.len();

    let ciphertext = &signed_data_der[ciphertext_offset..ciphertext_offset + 144];

    // KE and IV are fixed by deterministic_rng(). Decrypting the
    // final emitted ciphertext verifies that the inner KeyBlock
    // compatibility choices survived the complete public API path.
    let ephemeral_key = hex::decode("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0").unwrap();

    let iv: [u8; AES_BLOCK_SIZE] = hex::decode("000102030405060708090A0B0C0D0E0F")
        .unwrap()
        .try_into()
        .unwrap();

    let decrypt_provider = RustCryptoProvider::new();

    let padded_key_block = decrypt_provider
        .decrypt_cbc(ephemeral_key.as_slice(), &iv, ciphertext)
        .unwrap();

    let padding_length = *padded_key_block.last().unwrap() as usize;

    assert_eq!(padding_length, 11,);

    assert_eq!(
        &padded_key_block[padded_key_block.len() - padding_length..],
        &[0x0B; 11],
    );

    let key_block = &padded_key_block[..padded_key_block.len() - padding_length];

    assert_eq!(key_block.len(), 133,);

    // Annex B KeyBlock version is INTEGER 1.
    assert_eq!(&key_block[..6], &[0x30, 0x81, 0x82, 0x02, 0x01, 0x01,],);

    // Annex B wraps the Key Block Header in an id-data Attribute.
    let key_block_header_attribute = hex::decode(concat!(
        "301F",
        "06092A864886F70D010701",
        "3112",
        "0410",
        "41303235364B30544230304530303030",
    ))
    .unwrap();

    assert!(
        find_subslice(key_block, &key_block_header_attribute,).is_some(),
        "Annex B KeyBlock header Attribute not found",
    );

    // The SignedAttributes must preserve Annex B's published order:
    //
    // contentType
    // randomNonce
    // id-data / clear KBH
    // messageDigest
    //
    // Checking the first three adjacent attributes proves that the
    // raw compatibility path did not canonicalize the SET OF.
    let annex_b_signed_attribute_prefix = hex::decode(concat!(
        "3018",
        "06092A864886F70D010903",
        "310B",
        "06092A864886F70D010703",
        "3020",
        "060A2A864886F70D01091903",
        "3112",
        "0410",
        "167EB0E72781E4940112233445566778",
        "301F",
        "06092A864886F70D010701",
        "3112",
        "0410",
        "41303235364B30544230304530303030",
    ))
    .unwrap();

    assert!(
        find_subslice(&signed_data_der, &annex_b_signed_attribute_prefix,).is_some(),
        "Annex B SignedAttributes order not found",
    );

    // Annex B labels the RSA PKCS#1 v1.5 SHA-256 signature using
    // rsaEncryption with NULL parameters.
    let rsa_encryption = hex::decode("300D06092A864886F70D0101010500").unwrap();

    assert!(
        find_subslice(&signed_data_der, &rsa_encryption,).is_some(),
        "rsaEncryption AlgorithmIdentifier not found",
    );

    // Complete two-pass export includes CRLCA_KDH.
    assert!(
        find_subslice(&signed_data_der, KDH_CRL_DER,).is_some(),
        "KDH CRL not found in SignedData",
    );
}
