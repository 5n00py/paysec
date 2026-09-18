use cms::enveloped_data::EnvelopedData;
use cms::signed_data::SignerInfo;

use paysec_crypto::{
    AesCbc, CryptoProvider, RandomBytes, RsaOaepSha256Encrypt, RsaPkcs1v15Sha256Sign,
};

use zeroize::Zeroizing;

use cms::content_info::ContentInfo;

use der::Encode;

use crate::asn1::signed_data::{build_key_token_signed_data, wrap_signed_data};

use crate::{KdhCredential, KdhCrl, KrdCredential, Tr34CryptoError, Tr34Error};

use crate::asn1::enveloped_data::{build_enveloped_data, encode_padded_key_block};

use crate::asn1::signed_attributes::{
    build_two_pass_signed_attributes, signed_attributes_signing_der,
};

use crate::asn1::signer_info::build_signer_info;

const AES_128_KEY_LENGTH: usize = 16;
const AES_CBC_IV_LENGTH: usize = 16;

/// Construct the encrypted inner TR-34 key block.
///
/// This function performs the KDH-side cryptographic operations required to
/// produce the inner CMS EnvelopedData:
///
/// 1. Encode and pad the TR-34 KeyBlock.
/// 2. Generate the ephemeral AES-128 key KE.
/// 3. Generate the AES-CBC initialization vector.
/// 4. Encrypt the padded KeyBlock under KE.
/// 5. Encrypt KE under the KRD public key using RSAES-OAEP-SHA256.
/// 6. Construct the CMS EnvelopedData.
pub(crate) fn build_enveloped_key_block<P, K>(
    provider: &mut P,
    kdh_credential: &KdhCredential,
    krd_credential: &KrdCredential,
    krd_public_key: &K,
    clear_key: &[u8],
    key_block_header: &[u8],
) -> Result<EnvelopedData, Tr34CryptoError<<P as CryptoProvider>::Error>>
where
    P: RandomBytes + AesCbc<[u8]> + RsaOaepSha256Encrypt<K>,
    K: ?Sized,
{
    let padded_key_block = encode_padded_key_block(kdh_credential, clear_key, key_block_header)?;

    let mut ephemeral_key = Zeroizing::new([0u8; AES_128_KEY_LENGTH]);

    provider
        .fill_random(&mut ephemeral_key[..])
        .map_err(Tr34CryptoError::Crypto)?;

    let mut iv = [0u8; AES_CBC_IV_LENGTH];

    provider
        .fill_random(&mut iv)
        .map_err(Tr34CryptoError::Crypto)?;

    let encrypted_key_block = provider
        .encrypt_cbc(&ephemeral_key[..], &iv, padded_key_block.as_slice())
        .map_err(Tr34CryptoError::Crypto)?;

    let encrypted_ephemeral_key = provider
        .encrypt_oaep_sha256(krd_public_key, &ephemeral_key[..])
        .map_err(Tr34CryptoError::Crypto)?;

    Ok(build_enveloped_data(
        krd_credential,
        &encrypted_ephemeral_key,
        &iv,
        &encrypted_key_block,
    )?)
}

/// Construct a complete strict two-pass TR-34 KDH key token.
///
/// This performs the complete KDH-side key transport flow:
///
/// 1. Encode and encrypt the inner KeyBlock.
/// 2. Wrap KE for the KRD using RSAES-OAEP-SHA256.
/// 3. DER-encode the resulting EnvelopedData exactly once.
/// 4. Build the two-pass SignedAttributes over those exact bytes.
/// 5. Sign the attributes using the KDH signing key.
/// 6. Construct SignerInfo and SignedData.
/// 7. Include CRLCA_KDH.
/// 8. Wrap the SignedData in top-level CMS ContentInfo.
pub(crate) fn build_two_pass_key_token<P, KrdKey, KdhKey>(
    provider: &mut P,
    kdh_credential: &KdhCredential,
    krd_credential: &KrdCredential,
    krd_public_key: &KrdKey,
    kdh_signing_key: &KdhKey,
    clear_key: &[u8],
    key_block_header: &[u8],
    random_nonce: &[u8],
    kdh_crl: &KdhCrl,
) -> Result<ContentInfo, Tr34CryptoError<<P as CryptoProvider>::Error>>
where
    P: RandomBytes + AesCbc<[u8]> + RsaOaepSha256Encrypt<KrdKey> + RsaPkcs1v15Sha256Sign<KdhKey>,
    KrdKey: ?Sized,
    KdhKey: ?Sized,
{
    let enveloped_data = build_enveloped_key_block(
        provider,
        kdh_credential,
        krd_credential,
        krd_public_key,
        clear_key,
        key_block_header,
    )?;

    // This is the single authoritative encoding of the inner
    // EnvelopedData. These exact bytes are both digested by the signed
    // attributes and embedded as SignedData eContent.
    let encapsulated_content = enveloped_data.to_der().map_err(Tr34Error::from)?;

    let signer_info = build_two_pass_signer_info(
        provider,
        kdh_credential,
        kdh_signing_key,
        &encapsulated_content,
        random_nonce,
        key_block_header,
    )?;

    let signed_data =
        build_key_token_signed_data(&encapsulated_content, signer_info, Some(kdh_crl))?;

    Ok(wrap_signed_data(&signed_data)?)
}

/// Construct the CMS SignerInfo for a two-pass TR-34 key token.
///
/// `encapsulated_content` must be the exact DER bytes that will be placed
/// in the outer SignedData `eContent`.
///
/// This function:
///
/// 1. Constructs the two-pass SignedAttributes.
/// 2. Encodes the exact canonical DER bytes covered by the signature.
/// 3. Signs those bytes using RSA PKCS#1 v1.5 with SHA-256.
/// 4. Constructs the CMS SignerInfo.
///
/// The KDH signing key is supplied separately from `KdhCredential` so the
/// TR-34 layer remains independent of the provider's private-key
/// representation.
pub(crate) fn build_two_pass_signer_info<P, K>(
    provider: &P,
    kdh_credential: &KdhCredential,
    kdh_signing_key: &K,
    encapsulated_content: &[u8],
    random_nonce: &[u8],
    key_block_header: &[u8],
) -> Result<SignerInfo, Tr34CryptoError<<P as CryptoProvider>::Error>>
where
    P: RsaPkcs1v15Sha256Sign<K>,
    K: ?Sized,
{
    let signed_attributes =
        build_two_pass_signed_attributes(encapsulated_content, random_nonce, key_block_header)?;

    let signing_der = signed_attributes_signing_der(&signed_attributes)?;

    let signature = provider
        .sign_pkcs1v15_sha256(kdh_signing_key, &signing_der)
        .map_err(Tr34CryptoError::Crypto)?;

    Ok(build_signer_info(
        kdh_credential,
        signed_attributes,
        &signature,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use der::{Decode, Encode};

    use paysec_crypto_rustcrypto::{RsaPrivateKey, RsaPublicKey, RustCryptoProvider};
    use rand_core::{CryptoRng, Error as RandError, RngCore};

    use crate::asn1::enveloped_data::aes_128_cbc_algorithm_identifier;
    use paysec_crypto::RsaPkcs1v15Sha256Verify;

    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

    use cms::revocation::RevocationInfoChoice;
    use cms::signed_data::SignedData;

    use crate::oid::ID_SIGNED_DATA;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../tests/fixtures/kdh-certificate.der");

    const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("../tests/fixtures/krd-certificate.der");

    const KDH_PRIVATE_KEY_DER: &[u8] = include_bytes!("../tests/fixtures/kdh-private-key.der");

    const KDH_CRL_DER: &[u8] = include_bytes!("../tests/fixtures/kdh-crl.der");

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

    fn krd_public_key(credential: &KrdCredential) -> RsaPublicKey {
        let spki = credential.subject_public_key_info_der().unwrap();

        RsaPublicKey::from_public_key_der(&spki).unwrap()
    }

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

    fn kdh_private_key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_der(KDH_PRIVATE_KEY_DER).unwrap()
    }

    fn kdh_public_key(credential: &KdhCredential) -> RsaPublicKey {
        let spki = credential
            .certificate()
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();

        RsaPublicKey::from_public_key_der(&spki).unwrap()
    }

    #[test]
    fn builds_enveloped_key_block_using_provider_crypto() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let public_key = krd_public_key(&krd_credential);

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

        let enveloped_data = build_enveloped_key_block(
            &mut provider,
            &kdh_credential,
            &krd_credential,
            &public_key,
            &clear_key,
            b"A0256K0TB00E0000",
        )
        .unwrap();

        assert_eq!(enveloped_data.version, cms::content_info::CmsVersion::V0);

        assert!(enveloped_data.originator_info.is_none());

        assert!(enveloped_data.unprotected_attrs.is_none());

        let expected_iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        assert_eq!(
            enveloped_data.encrypted_content.content_enc_alg,
            aes_128_cbc_algorithm_identifier(&expected_iv,).unwrap()
        );

        let encrypted_key_block = enveloped_data
            .encrypted_content
            .encrypted_content
            .as_ref()
            .unwrap();

        assert_eq!(
            encrypted_key_block.as_bytes(),
            hex::decode(
                "7E817CE6F591CDAD7D50079032F8D824\
                 8287A599C699B2DDA97550DB9B7C7DB4\
                 5EADCF2C2FE88134B38618985E19DAC0\
                 50D7915D95053B360A7D17F54C3A481A\
                 081DDD821ADB1C88F859DC2FC8DFF432\
                 DBC706473758E227DA117781F59AD616\
                 78F0A750D0EC2DA877F8800985B1DCC\
                 907C252FE0BFE162FD227D11F635A4547"
            )
            .unwrap()
            .as_slice()
        );
    }

    #[test]
    fn enveloped_key_block_is_reproducible_with_deterministic_rng() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let public_key = krd_public_key(&krd_credential);

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let mut provider_a = RustCryptoProvider::with_rng(deterministic_rng());

        let mut provider_b = RustCryptoProvider::with_rng(deterministic_rng());

        let enveloped_a = build_enveloped_key_block(
            &mut provider_a,
            &kdh_credential,
            &krd_credential,
            &public_key,
            &clear_key,
            b"A0256K0TB00E0000",
        )
        .unwrap();

        let enveloped_b = build_enveloped_key_block(
            &mut provider_b,
            &kdh_credential,
            &krd_credential,
            &public_key,
            &clear_key,
            b"A0256K0TB00E0000",
        )
        .unwrap();

        assert_eq!(enveloped_a.to_der().unwrap(), enveloped_b.to_der().unwrap());
    }

    #[test]
    fn signs_two_pass_attributes_with_kdh_private_key() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let krd_public_key = krd_public_key(&krd_credential);

        let kdh_private_key = kdh_private_key();

        let kdh_public_key = kdh_public_key(&kdh_credential);

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let key_block_header = b"A0256K0TB00E0000";

        let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

        let enveloped_data = build_enveloped_key_block(
            &mut provider,
            &kdh_credential,
            &krd_credential,
            &krd_public_key,
            &clear_key,
            key_block_header,
        )
        .unwrap();

        // These are the exact bytes that will later become the outer
        // SignedData eContent.
        let encapsulated_content = enveloped_data.to_der().unwrap();

        let signer_info = build_two_pass_signer_info(
            &provider,
            &kdh_credential,
            &kdh_private_key,
            &encapsulated_content,
            &random_nonce,
            key_block_header,
        )
        .unwrap();

        let signed_attributes = signer_info.signed_attrs.as_ref().unwrap();

        let signing_der = signed_attributes_signing_der(signed_attributes).unwrap();

        provider
            .verify_pkcs1v15_sha256(
                &kdh_public_key,
                &signing_der,
                signer_info.signature.as_bytes(),
            )
            .unwrap();
    }

    #[test]
    fn two_pass_signature_binds_exact_encapsulated_content() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let kdh_private_key = kdh_private_key();

        let kdh_public_key = kdh_public_key(&kdh_credential);

        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let key_block_header = b"A0256K0TB00E0000";

        let provider = RustCryptoProvider::new();

        let signer_info = build_two_pass_signer_info(
            &provider,
            &kdh_credential,
            &kdh_private_key,
            b"original encapsulated content",
            &random_nonce,
            key_block_header,
        )
        .unwrap();

        let modified_attributes = build_two_pass_signed_attributes(
            b"modified encapsulated content",
            &random_nonce,
            key_block_header,
        )
        .unwrap();

        let modified_signing_der = signed_attributes_signing_der(&modified_attributes).unwrap();

        let result = provider.verify_pkcs1v15_sha256(
            &kdh_public_key,
            &modified_signing_der,
            signer_info.signature.as_bytes(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn builds_complete_two_pass_key_token() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let kdh_crl = KdhCrl::from_der(KDH_CRL_DER).unwrap();

        let krd_public_key = krd_public_key(&krd_credential);

        let kdh_private_key = kdh_private_key();

        let kdh_public_key = kdh_public_key(&kdh_credential);

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let key_block_header = b"A0256K0TB00E0000";

        let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

        let content_info = build_two_pass_key_token(
            &mut provider,
            &kdh_credential,
            &krd_credential,
            &krd_public_key,
            &kdh_private_key,
            &clear_key,
            key_block_header,
            &random_nonce,
            &kdh_crl,
        )
        .unwrap();

        assert_eq!(content_info.content_type, ID_SIGNED_DATA);

        let signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();

        assert_eq!(signed_data.version, cms::content_info::CmsVersion::V3);

        assert!(signed_data.certificates.is_none());

        let crls = signed_data.crls.as_ref().unwrap();

        assert_eq!(crls.0.len(), 1);

        match crls.0.get(0).unwrap() {
            RevocationInfoChoice::Crl(crl) => {
                assert_eq!(crl.to_der().unwrap(), KDH_CRL_DER);
            }

            other => {
                panic!("unexpected revocation information: {other:?}");
            }
        }

        let signer_info = signed_data.signer_infos.0.get(0).unwrap();

        let signed_attributes = signer_info.signed_attrs.as_ref().unwrap();

        let signing_der = signed_attributes_signing_der(signed_attributes).unwrap();

        provider
            .verify_pkcs1v15_sha256(
                &kdh_public_key,
                &signing_der,
                signer_info.signature.as_bytes(),
            )
            .unwrap();
    }
}
