use cms::content_info::CmsVersion;
use cms::enveloped_data::{EncryptedKey, KeyTransRecipientInfo};

use der::asn1::Any;
use der::{Decode, Encode, Sequence};

use pkcs1::RsaOaepParams;

use sha2::Sha256;

use spki::AlgorithmIdentifierOwned;

use crate::oid::{ID_SHA_256, MGF1, P_SPECIFIED, RSAES_OAEP};
use crate::profile::OaepParametersEncoding;
use crate::{KrdCredential, Tr34Error};

/// Annex B representation of RSAES-OAEP parameters.
///
/// Unlike PKCS #1 RSAES-OAEP-params, the published samples encode the
/// three component AlgorithmIdentifiers directly inside a SEQUENCE rather
/// than using the [0], [1], and [2] context-specific fields.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AnnexBOaepParameters {
    hash_algorithm: AlgorithmIdentifierOwned,
    mask_gen_algorithm: AlgorithmIdentifierOwned,
    p_source_algorithm: AlgorithmIdentifierOwned,
}

/// Construct the RSAES-OAEP AlgorithmIdentifier required by TR-34.
///
/// Both encodings describe the same cryptographic operation:
///
/// - SHA-256
/// - MGF1 with SHA-256
/// - empty label
///
/// Only the ASN.1 representation of the parameters differs.
pub(crate) fn rsa_oaep_sha256_algorithm_identifier(
    encoding: OaepParametersEncoding,
) -> Result<AlgorithmIdentifierOwned, Tr34Error> {
    let parameters = match encoding {
        OaepParametersEncoding::Pkcs1 => {
            let parameters = RsaOaepParams::new::<Sha256>().to_der()?;

            Any::from_der(&parameters)?
        }

        OaepParametersEncoding::AnnexBSample => annex_b_oaep_parameters()?,
    };

    Ok(AlgorithmIdentifierOwned {
        oid: RSAES_OAEP,
        parameters: Some(parameters),
    })
}

fn annex_b_oaep_parameters() -> Result<Any, Tr34Error> {
    let null = Any::from_der(&[0x05, 0x00])?;

    let empty_octet_string = Any::from_der(&[0x04, 0x00])?;

    // Annex B encodes the top-level SHA-256 AlgorithmIdentifier with NULL.
    let hash_algorithm = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: Some(null),
    };

    // Inside MGF1, the sample encodes SHA-256 without parameters.
    let mgf_hash_algorithm = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    };

    let mask_gen_algorithm = AlgorithmIdentifierOwned {
        oid: MGF1,
        parameters: Some(Any::encode_from(&mgf_hash_algorithm)?),
    };

    let p_source_algorithm = AlgorithmIdentifierOwned {
        oid: P_SPECIFIED,
        parameters: Some(empty_octet_string),
    };

    let parameters = AnnexBOaepParameters {
        hash_algorithm,
        mask_gen_algorithm,
        p_source_algorithm,
    };

    Ok(Any::encode_from(&parameters)?)
}

/// Construct the CMS KeyTransRecipientInfo for a TR-34 KRD.
///
/// `encrypted_key` is the ephemeral symmetric key KE after RSAES-OAEP
/// encryption using the KRD's public encipherment key.
///
/// The cryptographic operation is deliberately performed outside this
/// ASN.1 layer so that software and HSM-backed providers can produce the
/// encrypted key without coupling TR-34 encoding to a particular provider.
pub(crate) fn build_key_transport_recipient_info(
    krd_credential: &KrdCredential,
    encrypted_key: &[u8],
    oaep_parameters: OaepParametersEncoding,
) -> Result<KeyTransRecipientInfo, Tr34Error> {
    Ok(KeyTransRecipientInfo {
        version: CmsVersion::V0,
        rid: krd_credential.recipient_identifier(),
        key_enc_alg: rsa_oaep_sha256_algorithm_identifier(oaep_parameters)?,
        enc_key: EncryptedKey::new(encrypted_key.to_vec())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use cms::enveloped_data::RecipientIdentifier;

    use paysec_crypto::RsaOaepSha256Encrypt;

    use paysec_crypto_rustcrypto::{RsaPublicKey, RustCryptoProvider};

    use rand_core::{CryptoRng, Error as RandError, RngCore};

    use rsa::pkcs8::DecodePublicKey;

    const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("../../tests/fixtures/krd-certificate.der");

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

    #[test]
    fn oaep_algorithm_identifier_uses_sha256_and_mgf1_sha256() {
        let algorithm =
            rsa_oaep_sha256_algorithm_identifier(OaepParametersEncoding::Pkcs1).unwrap();

        let encoded = algorithm.to_der().unwrap();

        let expected = hex::decode(
            "303C\
             06092A864886F70D010107\
             302F\
             A00F\
             300D\
             0609608648016503040201\
             0500\
             A11C\
             301A\
             06092A864886F70D010108\
             300D\
             0609608648016503040201\
             0500",
        )
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn key_transport_recipient_info_uses_krd_issuer_and_serial_number() {
        let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let encrypted_key = vec![0xAA; 256];

        let recipient_info = build_key_transport_recipient_info(
            &credential,
            &encrypted_key,
            OaepParametersEncoding::Pkcs1,
        )
        .unwrap();

        assert_eq!(recipient_info.version, CmsVersion::V0);

        assert_eq!(
            recipient_info.rid,
            RecipientIdentifier::IssuerAndSerialNumber(credential.issuer_and_serial_number())
        );

        assert_eq!(recipient_info.key_enc_alg.oid, RSAES_OAEP);

        assert_eq!(recipient_info.enc_key.as_bytes(), encrypted_key.as_slice());
    }

    #[test]
    fn key_transport_recipient_info_round_trips_through_der() {
        let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let encrypted_key = vec![0xAA; 256];

        let recipient_info = build_key_transport_recipient_info(
            &credential,
            &encrypted_key,
            OaepParametersEncoding::Pkcs1,
        )
        .unwrap();

        let encoded = recipient_info.to_der().unwrap();

        let decoded = KeyTransRecipientInfo::from_der(&encoded).unwrap();

        assert_eq!(decoded, recipient_info);
    }

    #[test]
    fn builds_key_transport_recipient_info_from_rustcrypto_oaep() {
        let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let spki = credential.subject_public_key_info_der().unwrap();

        let public_key = RsaPublicKey::from_public_key_der(&spki).unwrap();

        let ephemeral_key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];

        // SHA-256 OAEP consumes a 32-byte seed.
        let oaep_seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let mut provider = RustCryptoProvider::with_rng(FixedRng::new(oaep_seed));

        let encrypted_key = provider
            .encrypt_oaep_sha256(&public_key, &ephemeral_key)
            .unwrap();

        assert_eq!(encrypted_key.len(), 256);

        let recipient_info = build_key_transport_recipient_info(
            &credential,
            &encrypted_key,
            OaepParametersEncoding::Pkcs1,
        )
        .unwrap();

        assert_eq!(recipient_info.enc_key.as_bytes(), encrypted_key.as_slice());

        assert_eq!(recipient_info.key_enc_alg.oid, RSAES_OAEP);
    }

    #[test]
    fn oaep_wrapped_ephemeral_key_is_reproducible() {
        let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let spki = credential.subject_public_key_info_der().unwrap();

        let public_key = RsaPublicKey::from_public_key_der(&spki).unwrap();

        let ephemeral_key = [0x42; 16];

        let seed = [0xA5; 32];

        let mut provider_a = RustCryptoProvider::with_rng(FixedRng::new(seed));

        let mut provider_b = RustCryptoProvider::with_rng(FixedRng::new(seed));

        let encrypted_a = provider_a
            .encrypt_oaep_sha256(&public_key, &ephemeral_key)
            .unwrap();

        let encrypted_b = provider_b
            .encrypt_oaep_sha256(&public_key, &ephemeral_key)
            .unwrap();

        assert_eq!(encrypted_a, encrypted_b);

        let ktri_a = build_key_transport_recipient_info(
            &credential,
            &encrypted_a,
            OaepParametersEncoding::Pkcs1,
        )
        .unwrap();

        let ktri_b = build_key_transport_recipient_info(
            &credential,
            &encrypted_b,
            OaepParametersEncoding::Pkcs1,
        )
        .unwrap();
        assert_eq!(ktri_a.to_der().unwrap(), ktri_b.to_der().unwrap());
    }

    #[test]
    fn annex_b_oaep_algorithm_identifier_uses_sample_parameter_encoding() {
        let algorithm =
            rsa_oaep_sha256_algorithm_identifier(OaepParametersEncoding::AnnexBSample).unwrap();

        let encoded = algorithm.to_der().unwrap();

        let expected = hex::decode(concat!(
            "3045",
            "06092A864886F70D010107",
            "3038",
            "300D",
            "0609608648016503040201",
            "0500",
            "3018",
            "06092A864886F70D010108",
            "300B",
            "0609608648016503040201",
            "300D",
            "06092A864886F70D010109",
            "0400",
        ))
        .unwrap();

        assert_eq!(encoded, expected,);
    }
}
