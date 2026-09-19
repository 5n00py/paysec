use cms::signed_data::SignerInfo;

use paysec_crypto::{
    AesCbc, CryptoProvider, RandomBytes, RsaOaepSha256Encrypt, RsaPkcs1v15Sha256Sign,
};

use zeroize::Zeroizing;

use cms::content_info::ContentInfo;

use der::Encode;

use crate::{KdhCredential, KdhCrl, KrdCredential, Tr34CryptoError, Tr34Error, Tr34Profile};

use crate::asn1::enveloped_data::{
    build_enveloped_data, encode_annex_b_enveloped_data, encode_padded_key_block,
};

use crate::asn1::signed_attributes::{
    build_two_pass_signed_attributes, encode_annex_b_two_pass_signed_attributes,
    signed_attributes_signing_der,
};

use crate::asn1::signed_data::{
    build_key_token_signed_data, encode_signed_data_with_signer_info_der, wrap_signed_data,
    wrap_signed_data_der,
};

use crate::asn1::signer_info::{build_signer_info, encode_signer_info_with_signed_attributes_der};

use crate::profile::{EncodingPolicy, EncryptedContentLayout, SignedAttributesOrder};

const AES_128_KEY_LENGTH: usize = 16;
const AES_CBC_IV_LENGTH: usize = 16;

/// Parameters for a two-pass TR-34 key export operation.
///
/// The cryptographic key handles are supplied separately to
/// [`export_key_two_pass`] because their concrete representation belongs
/// to the crypto provider rather than the TR-34 protocol layer.
///
/// The request fields are intentionally private so that additional TR-34
/// profile or compatibility options can be introduced later without
/// exposing the internal representation as part of the public API.
pub struct TwoPassKeyExportRequest<'a> {
    kdh_credential: &'a KdhCredential,
    krd_credential: &'a KrdCredential,
    clear_key: &'a [u8],
    key_block_header: &'a [u8],
    krd_random_nonce: &'a [u8],
    kdh_crl: &'a KdhCrl,
    profile: Tr34Profile,
}

impl<'a> TwoPassKeyExportRequest<'a> {
    /// Construct a two-pass TR-34 key export request.
    ///
    /// The request uses [`Tr34Profile::Strict`] by default. A different
    /// supported encoding profile can be selected with
    /// [`TwoPassKeyExportRequest::with_profile`].
    ///
    /// `krd_random_nonce` is the random nonce received from the KRD for
    /// this transaction.
    ///
    /// `kdh_crl` is required by the strict TR-34 encoding path.
    #[must_use]
    pub fn new(
        kdh_credential: &'a KdhCredential,
        krd_credential: &'a KrdCredential,
        clear_key: &'a [u8],
        key_block_header: &'a [u8],
        krd_random_nonce: &'a [u8],
        kdh_crl: &'a KdhCrl,
    ) -> Self {
        Self {
            kdh_credential,
            krd_credential,
            clear_key,
            key_block_header,
            krd_random_nonce,
            kdh_crl,
            profile: Tr34Profile::Strict,
        }
    }

    /// Select the TR-34 encoding profile for this export.
    #[must_use]
    pub fn with_profile(mut self, profile: Tr34Profile) -> Self {
        self.profile = profile;
        self
    }
}

/// Construct and encode the encrypted inner TR-34 key block.
///
/// The returned bytes are the authoritative EnvelopedData encoding that
/// will later be both digested by SignedAttributes and embedded as
/// SignedData eContent.
pub(crate) fn encode_enveloped_key_block<P, K>(
    provider: &mut P,
    kdh_credential: &KdhCredential,
    krd_credential: &KrdCredential,
    krd_public_key: &K,
    clear_key: &[u8],
    key_block_header: &[u8],
    policy: EncodingPolicy,
) -> Result<Vec<u8>, Tr34CryptoError<<P as CryptoProvider>::Error>>
where
    P: RandomBytes + AesCbc<[u8]> + RsaOaepSha256Encrypt<K>,
    K: ?Sized,
{
    let padded_key_block = encode_padded_key_block(
        kdh_credential,
        clear_key,
        key_block_header,
        policy.key_block_version,
        policy.key_block_header,
    )?;

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

    let encoded = match policy.encrypted_content_layout {
        EncryptedContentLayout::Cms => build_enveloped_data(
            krd_credential,
            &encrypted_ephemeral_key,
            &iv,
            &encrypted_key_block,
            policy.oaep_parameters,
        )?
        .to_der()
        .map_err(Tr34Error::from)?,

        EncryptedContentLayout::AnnexB2019 => encode_annex_b_enveloped_data(
            krd_credential,
            &encrypted_ephemeral_key,
            &iv,
            &encrypted_key_block,
            policy.oaep_parameters,
        )?,
    };

    Ok(encoded)
}

/// Construct a complete two-pass TR-34 KDH key token.
///
/// This performs the complete KDH-side key transport flow:
///
/// 1. Encode and encrypt the inner KeyBlock.
/// 2. Wrap KE for the KRD using RSAES-OAEP-SHA256.
/// 3. Encode the resulting EnvelopedData exactly once.
/// 4. Build the two-pass SignedAttributes over those exact bytes.
/// 5. Sign the exact SignedAttributes representation selected by the profile.
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
    policy: EncodingPolicy,
) -> Result<ContentInfo, Tr34CryptoError<<P as CryptoProvider>::Error>>
where
    P: RandomBytes + AesCbc<[u8]> + RsaOaepSha256Encrypt<KrdKey> + RsaPkcs1v15Sha256Sign<KdhKey>,
    KrdKey: ?Sized,
    KdhKey: ?Sized,
{
    let encapsulated_content = encode_enveloped_key_block(
        provider,
        kdh_credential,
        krd_credential,
        krd_public_key,
        clear_key,
        key_block_header,
        policy,
    )?;

    // This is the single authoritative encoding of the inner
    // EnvelopedData. These exact bytes are both digested by the signed
    // attributes and embedded as SignedData eContent.

    match policy.signed_attributes_order {
        SignedAttributesOrder::Der => {
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

        SignedAttributesOrder::AnnexBSample => {
            let signer_info_der = encode_annex_b_two_pass_signer_info(
                provider,
                kdh_credential,
                kdh_signing_key,
                &encapsulated_content,
                random_nonce,
                key_block_header,
            )?;

            let signed_data_der = encode_signed_data_with_signer_info_der(
                &encapsulated_content,
                &signer_info_der,
                Some(kdh_crl),
            )?;

            Ok(wrap_signed_data_der(&signed_data_der)?)
        }
    }
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

/// Construct and encode the SignerInfo for the Annex B compatibility path.
///
/// The signature is calculated over the exact sample-ordered SignedAttributes
/// encoding using the normal SET OF tag. The same attribute contents are then
/// embedded in SignerInfo using the `[0] IMPLICIT` tag without passing through
/// the canonical CMS SignedAttributes representation.
pub(crate) fn encode_annex_b_two_pass_signer_info<P, K>(
    provider: &P,
    kdh_credential: &KdhCredential,
    kdh_signing_key: &K,
    encapsulated_content: &[u8],
    random_nonce: &[u8],
    key_block_header: &[u8],
) -> Result<Vec<u8>, Tr34CryptoError<<P as CryptoProvider>::Error>>
where
    P: RsaPkcs1v15Sha256Sign<K>,
    K: ?Sized,
{
    let signed_attributes = encode_annex_b_two_pass_signed_attributes(
        encapsulated_content,
        random_nonce,
        key_block_header,
    )?;

    let signature = provider
        .sign_pkcs1v15_sha256(kdh_signing_key, signed_attributes.signing_der())
        .map_err(Tr34CryptoError::Crypto)?;

    Ok(encode_signer_info_with_signed_attributes_der(
        kdh_credential,
        signed_attributes.signer_info_der(),
        &signature,
    )?)
}

/// Export a key using the selected two-pass TR-34 encoding profile.
///
/// Requests created with [`TwoPassKeyExportRequest::new`] use
/// [`Tr34Profile::Strict`] by default.
///
/// The returned byte vector is the complete DER-encoded CMS ContentInfo
/// containing the TR-34 KDH key token.
///
/// `krd_public_key` is the provider-specific public encryption-key handle
/// corresponding to the KRD credential.
///
/// `kdh_signing_key` is the provider-specific private signing-key handle
/// corresponding to the KDH credential.
///
/// This operation does not validate certificate paths, certificate or CRL
/// freshness, revocation status, key usage, or that the supplied provider
/// key handles correspond to the supplied credentials.
pub fn export_key_two_pass<P, KrdKey, KdhKey>(
    provider: &mut P,
    request: TwoPassKeyExportRequest<'_>,
    krd_public_key: &KrdKey,
    kdh_signing_key: &KdhKey,
) -> Result<Vec<u8>, Tr34CryptoError<<P as CryptoProvider>::Error>>
where
    P: RandomBytes + AesCbc<[u8]> + RsaOaepSha256Encrypt<KrdKey> + RsaPkcs1v15Sha256Sign<KdhKey>,
    KrdKey: ?Sized,
    KdhKey: ?Sized,
{
    let policy = EncodingPolicy::for_profile(request.profile);

    let content_info = build_two_pass_key_token(
        provider,
        request.kdh_credential,
        request.krd_credential,
        krd_public_key,
        kdh_signing_key,
        request.clear_key,
        request.key_block_header,
        request.krd_random_nonce,
        request.kdh_crl,
        policy,
    )?;

    content_info
        .to_der()
        .map_err(Tr34Error::from)
        .map_err(Tr34CryptoError::Tr34)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cms::revocation::RevocationInfoChoice;
    use cms::signed_data::SignedData;

    use der::{Decode, Encode};

    use paysec_crypto::RsaPkcs1v15Sha256Verify;

    use paysec_crypto_rustcrypto::{RsaPrivateKey, RsaPublicKey, RustCryptoProvider};

    use rand_core::{CryptoRng, Error as RandError, RngCore};

    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

    use crate::asn1::enveloped_data::aes_128_cbc_algorithm_identifier;

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

    fn kdh_private_key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_der(KDH_PRIVATE_KEY_DER).unwrap()
    }

    fn kdh_public_key() -> RsaPublicKey {
        let certificate = x509_cert::Certificate::from_der(KDH_CERTIFICATE_DER).unwrap();

        let spki = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();

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

    /// Construct the complete deterministic strict two-pass KTKDH and
    /// return its top-level ContentInfo DER encoding.
    ///
    /// The complete token is deterministic because:
    ///
    /// - KE is fixed by `deterministic_rng()`.
    /// - IV is fixed by `deterministic_rng()`.
    /// - the RSAES-OAEP SHA-256 seed is fixed by `deterministic_rng()`.
    /// - RSA PKCS#1 v1.5 SHA-256 signing is deterministic.
    /// - all ASN.1 output is DER encoded.
    fn deterministic_two_pass_key_token_der() -> Vec<u8> {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let kdh_crl = KdhCrl::from_der(KDH_CRL_DER).unwrap();

        let krd_public_key = krd_public_key(&krd_credential);

        let kdh_private_key = kdh_private_key();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let key_block_header = b"A0256K0TB00E0000";

        let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

        build_two_pass_key_token(
            &mut provider,
            &kdh_credential,
            &krd_credential,
            &krd_public_key,
            &kdh_private_key,
            &clear_key,
            key_block_header,
            &random_nonce,
            &kdh_crl,
            EncodingPolicy::for_profile(Tr34Profile::Strict),
        )
        .unwrap()
        .to_der()
        .unwrap()
    }

    #[test]
    fn builds_enveloped_key_block_using_provider_crypto() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let public_key = krd_public_key(&krd_credential);

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

        let encoded = encode_enveloped_key_block(
            &mut provider,
            &kdh_credential,
            &krd_credential,
            &public_key,
            &clear_key,
            b"A0256K0TB00E0000",
            EncodingPolicy::for_profile(Tr34Profile::Strict),
        )
        .unwrap();

        let enveloped_data = cms::enveloped_data::EnvelopedData::from_der(&encoded).unwrap();

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

        let encoded_a = encode_enveloped_key_block(
            &mut provider_a,
            &kdh_credential,
            &krd_credential,
            &public_key,
            &clear_key,
            b"A0256K0TB00E0000",
            EncodingPolicy::for_profile(Tr34Profile::Strict),
        )
        .unwrap();

        let encoded_b = encode_enveloped_key_block(
            &mut provider_b,
            &kdh_credential,
            &krd_credential,
            &public_key,
            &clear_key,
            b"A0256K0TB00E0000",
            EncodingPolicy::for_profile(Tr34Profile::Strict),
        )
        .unwrap();

        assert_eq!(encoded_a, encoded_b,);
    }

    #[test]
    fn signs_two_pass_attributes_with_kdh_private_key() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let krd_public_key = krd_public_key(&krd_credential);

        let kdh_private_key = kdh_private_key();

        let kdh_public_key = kdh_public_key();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let key_block_header = b"A0256K0TB00E0000";

        let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

        let encapsulated_content = encode_enveloped_key_block(
            &mut provider,
            &kdh_credential,
            &krd_credential,
            &krd_public_key,
            &clear_key,
            key_block_header,
            EncodingPolicy::for_profile(Tr34Profile::Strict),
        )
        .unwrap();

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

        let kdh_public_key = kdh_public_key();

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

        let kdh_public_key = kdh_public_key();

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
            EncodingPolicy::for_profile(Tr34Profile::Strict),
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

    #[test]
    fn complete_two_pass_key_token_is_reproducible() {
        let token_a = deterministic_two_pass_key_token_der();

        let token_b = deterministic_two_pass_key_token_der();

        assert_eq!(token_a, token_b);
    }

    #[test]
    fn encodes_expected_complete_two_pass_key_token() {
        let actual = deterministic_two_pass_key_token_der();

        let expected = hex::decode(concat!(
            "3082065706092A864886F70D010702A082064830820644020103310D300B0609",
            "6086480165030402013082026306092A864886F70D010703A082025404820250",
            "3082024C0201003182019530820191020100304A3041310B3009060355040613",
            "02555331153013060355040A130C545233342053616D706C6573311B30190603",
            "5504031312545233342053616D706C65204341204B524402053400000007303C",
            "06092A864886F70D010107302FA00F300D06096086480165030402010500A11C",
            "301A06092A864886F70D010108300D0609608648016503040201050004820100",
            "4812E7D8589EF7E8D21C543D7A191A7EE46D37DACD439FD7F4509C95B0F6375C",
            "0AB5564B1B5FC5344F70A1F291A9A667D5D3B0E3BE0AA8239DD791350E6923D2",
            "AF8065DF7E71F6628854752E49DDB55545574FA32217A128DB64B19C1BF29813",
            "0F708BCFA4B66D583A1EA73C0DFA1F7CE1B7ED629766448C7B524EFCD36CFECA",
            "E7C7941F708C5CEBF9DE2812D1448DF89C6A46FACFD9ABA9608879D6DF8F07D9",
            "DE74B113BA99B41C888EA90A6BEFE73771FB7B06DDC9D5BC33CB30819E42DCB4",
            "1C164A2FE1215B1CAAFD00F4EDE51D920761C6D7000B6A250F5C9476C15D8E1E",
            "CF6AF8726F7FAFD525D822D9EF236F35B18E5234D831C1F05FB095DFD22C6642",
            "3081AD06092A864886F70D010701301D06096086480165030401020410000102",
            "030405060708090A0B0C0D0E0F8081807E817CE6F591CDAD7D50079032F8D824",
            "8287A599C699B2DDA97550DB9B7C7DB45EADCF2C2FE88134B38618985E19DAC0",
            "50D7915D95053B360A7D17F54C3A481A081DDD821ADB1C88F859DC2FC8DFF432",
            "DBC706473758E227DA117781F59AD61678F0A750D0EC2DA877F8800985B1DCC9",
            "07C252FE0BFE162FD227D11F635A4547A18201BF308201BB3081A4020101300D",
            "06092A864886F70D01010B05003041310B300906035504061302555331153013",
            "060355040A130C545233342053616D706C6573311B3019060355040313125452",
            "33342053616D706C65204341204B4448170D3236303931383138333734335A17",
            "0D3336303931353138333734335AA02F302D301F0603551D2304183016801423",
            "39428F77196E22FEF8B59016F3B3BD7CD98784300A0603551D14040302010130",
            "0D06092A864886F70D01010B050003820101004673D355A53E39BEBA461C1365",
            "1280C0A0FA76305BF59B78DADFA427D84CAC1D69B0E7A84C3803E234B7C98CC2",
            "8302DBDDDBA0C07BF8D40157BD9DA6803BEAC49D4A78674A6DCA2CA13A941220",
            "C2D7D8A14085B76483CA54F236313678725716C55BEC97D27B5028148033A941",
            "BE97EF0823AA97A4167FCD9378527354B066B0B9CF66C7375357AFCD75A9C443",
            "F23DE7C60FED18FB9DC8F16F231A91528E2A1FFA79FA241748DA130BBCD4125D",
            "B49C053412A7A9057563E424233BCE6B6D6D0C0B72BABC7C96236CAD5103D8E4",
            "516DE3BAA931A6E6504EBCAB334057DBCE0DFE9782961960602E91AAFA8FA170",
            "36C75E3ADCC7EAFA142C06115F6317DD9A57503182020430820200020101304A",
            "3041310B300906035504061302555331153013060355040A130C545233342053",
            "616D706C6573311B301906035504031312545233342053616D706C6520434120",
            "4B444802053400000006300B0609608648016503040201A0818E301806092A86",
            "4886F70D010903310B06092A864886F70D010703301F06092A864886F70D0107",
            "013112041041303235364B305442303045303030303020060A2A864886F70D01",
            "09190331120410167EB0E72781E4940112233445566778302F06092A864886F7",
            "0D0109043122042028B4116D708E845C8EF357289234F517AE8577F55B2132A7",
            "1722902168273EAF300D06092A864886F70D01010B05000482010010FF27E3E4",
            "82A2A2E04ED510D5738D34D6DCB305940412A823ADD7FCD9F4949241538A7B38",
            "CB7236C36745290E0C62EB1C9ECFE890EA582E8AD63E81218440779C8DCAE51B",
            "B3ABD00AE99510F4B93E6FA33E8EC028E2281E81E2C8FCF10D454D6383697DAB",
            "13B9F96875A561DF4447F0EC77E609A6E3D759097EC80FE7C45CA2D4969F0BB2",
            "579308BAA1E653DAF7ACA049C1E2F2F2BC728328020B142B7D2B735FF5824398",
            "6DD94C6B6903DA5ACE42EDEDF1597E5621050BCF83D0152211001F303F29FAC9",
            "AE0A4FCF669391148C52910D933EF14DB5FBEE624658E47A6522A341DECE6DBD",
            "1ADBCF7972B3008C04E7DB74B546EBE76D7D903B0C4A547F7C52A5",
        ))
        .unwrap();

        assert_eq!(actual.len(), 1627,);

        assert_eq!(actual, expected,);
    }

    #[test]
    fn two_pass_key_export_request_defaults_to_strict_profile() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let kdh_crl = KdhCrl::from_der(KDH_CRL_DER).unwrap();

        let request = TwoPassKeyExportRequest::new(
            &kdh_credential,
            &krd_credential,
            b"0123456789ABCDEF",
            b"A0256K0TB00E0000",
            b"0123456789ABCDEF",
            &kdh_crl,
        );

        assert_eq!(request.profile, Tr34Profile::Strict,);
    }

    #[test]
    fn two_pass_key_export_request_uses_selected_profile() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let kdh_crl = KdhCrl::from_der(KDH_CRL_DER).unwrap();

        let request = TwoPassKeyExportRequest::new(
            &kdh_credential,
            &krd_credential,
            b"0123456789ABCDEF",
            b"A0256K0TB00E0000",
            b"0123456789ABCDEF",
            &kdh_crl,
        )
        .with_profile(Tr34Profile::AnnexB2019);

        assert_eq!(request.profile, Tr34Profile::AnnexB2019,);
    }

    #[test]
    fn annex_b_profile_uses_compatibility_enveloped_data_layout() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let public_key = krd_public_key(&krd_credential);

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let mut provider = RustCryptoProvider::with_rng(deterministic_rng());

        let encoded = encode_enveloped_key_block(
            &mut provider,
            &kdh_credential,
            &krd_credential,
            &public_key,
            &clear_key,
            b"A0256K0TB00E0000",
            EncodingPolicy::for_profile(Tr34Profile::AnnexB2019),
        )
        .unwrap();

        assert!(cms::enveloped_data::EnvelopedData::from_der(&encoded,).is_err(),);
    }
}
