use cms::content_info::{CmsVersion, ContentInfo};

use cms::signed_data::SignedData;

use der::{Decode, Encode};

use paysec_crypto_rustcrypto::{RsaPrivateKey, RsaPublicKey, RustCryptoProvider};

use paysec_tr34::{
    KdhCredential, KdhCrl, KrdCredential, TwoPassKeyExportRequest, export_key_two_pass,
};

use rand_core::{CryptoRng, Error as RandError, RngCore};

use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/kdh-certificate.der");

const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/krd-certificate.der");

const KDH_PRIVATE_KEY_DER: &[u8] = include_bytes!("fixtures/kdh-private-key.der");

const KDH_CRL_DER: &[u8] = include_bytes!("fixtures/kdh-crl.der");

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

    let oaep_seed = vec![0xA5; 32];

    let mut bytes = Vec::with_capacity(64);

    bytes.extend_from_slice(&ephemeral_key);

    bytes.extend_from_slice(&iv);

    bytes.extend_from_slice(&oaep_seed);

    FixedRng::new(bytes)
}

#[test]
fn exports_two_pass_key_token_through_public_api() {
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

    let request = TwoPassKeyExportRequest::new(
        &kdh_credential,
        &krd_credential,
        &clear_key,
        b"A0256K0TB00E0000",
        &random_nonce,
        &kdh_crl,
    );

    let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

    let token =
        export_key_two_pass(&mut provider, request, &krd_public_key, &kdh_private_key).unwrap();

    // The public API returns the complete wire-level ContentInfo.
    let content_info = ContentInfo::from_der(&token).unwrap();

    assert_eq!(
        content_info.content_type.to_string(),
        "1.2.840.113549.1.7.2"
    );

    let signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();

    assert_eq!(signed_data.version, CmsVersion::V3);

    assert!(signed_data.certificates.is_none());

    assert!(signed_data.crls.is_some());

    assert_eq!(signed_data.signer_infos.0.len(), 1);
}
