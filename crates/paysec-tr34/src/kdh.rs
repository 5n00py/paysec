use cms::enveloped_data::EnvelopedData;

use paysec_crypto::{AesCbc, CryptoProvider, RandomBytes, RsaOaepSha256Encrypt};

use zeroize::Zeroizing;

use crate::asn1::enveloped_data::{build_enveloped_data, encode_padded_key_block};

use crate::{KdhCredential, KrdCredential, Tr34CryptoError};

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
///
/// The KRD public key is supplied separately from `KrdCredential` so the
/// TR-34 layer remains independent of any concrete cryptographic provider's
/// public-key representation.
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
    // Perform deterministic encoding before consuming provider randomness.
    //
    // This buffer contains Kn in clear form and is zeroized on drop.
    let padded_key_block = encode_padded_key_block(kdh_credential, clear_key, key_block_header)?;

    // KE is sensitive key material and must be zeroized on drop.
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

#[cfg(test)]
mod tests {
    use super::*;

    use der::Encode;

    use paysec_crypto_rustcrypto::{RsaPublicKey, RustCryptoProvider};

    use rand_core::{CryptoRng, Error as RandError, RngCore};

    use rsa::pkcs8::DecodePublicKey;

    use crate::asn1::enveloped_data::aes_128_cbc_algorithm_identifier;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../tests/fixtures/kdh-certificate.der");

    const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("../tests/fixtures/krd-certificate.der");

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
}
