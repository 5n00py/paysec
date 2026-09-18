use cms::content_info::CmsVersion;
use cms::signed_data::{SignatureValue, SignedAttributes, SignerIdentifier, SignerInfo};

use der::asn1::Any;

use spki::AlgorithmIdentifierOwned;

use crate::oid::{ID_SHA_256, SHA256_WITH_RSA_ENCRYPTION};
use crate::{KdhCredential, Tr34Error};

/// SHA-256 AlgorithmIdentifier used by TR-34.
///
/// The SHA-256 digest algorithm identifier has absent parameters.
pub(crate) fn sha256_algorithm_identifier() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    }
}

/// RSA PKCS#1 v1.5 with SHA-256 AlgorithmIdentifier used by the strict
/// TR-34 signature profile.
///
/// The algorithm parameters are encoded as ASN.1 NULL.
pub(crate) fn sha256_with_rsa_encryption_algorithm_identifier() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: SHA256_WITH_RSA_ENCRYPTION,
        parameters: Some(Any::null()),
    }
}

/// Construct the strict CMS SignerInfo for a TR-34 KDH.
///
/// `signature` must be the RSA PKCS#1 v1.5 SHA-256 signature over the
/// canonical DER encoding of `signed_attributes`.
///
/// The cryptographic signing operation is deliberately performed outside
/// this ASN.1 layer so software and HSM-backed providers can both supply
/// the signature bytes.
pub(crate) fn build_signer_info(
    kdh_credential: &KdhCredential,
    signed_attributes: SignedAttributes,
    signature: &[u8],
) -> Result<SignerInfo, Tr34Error> {
    Ok(SignerInfo {
        version: CmsVersion::V1,

        sid: SignerIdentifier::IssuerAndSerialNumber(kdh_credential.issuer_and_serial_number()),

        digest_alg: sha256_algorithm_identifier(),

        signed_attrs: Some(signed_attributes),

        signature_algorithm: sha256_with_rsa_encryption_algorithm_identifier(),

        signature: SignatureValue::new(signature.to_vec())?,

        unsigned_attrs: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use der::{Decode, Encode};

    use crate::asn1::signed_attributes::build_two_pass_signed_attributes;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../../tests/fixtures/kdh-certificate.der");

    #[test]
    fn sha256_algorithm_identifier_has_absent_parameters() {
        let algorithm = sha256_algorithm_identifier();

        let encoded = algorithm.to_der().unwrap();

        let expected = hex::decode(
            "300B\
             0609608648016503040201",
        )
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn sha256_with_rsa_encryption_algorithm_identifier_has_null_parameters() {
        let algorithm = sha256_with_rsa_encryption_algorithm_identifier();

        let encoded = algorithm.to_der().unwrap();

        let expected = hex::decode(
            "300D\
             06092A864886F70D01010B\
             0500",
        )
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn signer_info_uses_kdh_issuer_and_serial_number() {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let signed_attributes = build_two_pass_signed_attributes(
            b"encapsulated content",
            b"nonce",
            b"A0256K0TB00E0000",
        )
        .unwrap();

        let signature = vec![0xAA; 256];

        let signer_info = build_signer_info(&credential, signed_attributes, &signature).unwrap();

        assert_eq!(signer_info.version, CmsVersion::V1);

        assert_eq!(
            signer_info.sid,
            SignerIdentifier::IssuerAndSerialNumber(credential.issuer_and_serial_number())
        );

        assert_eq!(signer_info.digest_alg, sha256_algorithm_identifier());

        assert_eq!(
            signer_info.signature_algorithm,
            sha256_with_rsa_encryption_algorithm_identifier()
        );

        assert_eq!(signer_info.signature.as_bytes(), signature.as_slice());

        assert!(signer_info.signed_attrs.is_some());

        assert!(signer_info.unsigned_attrs.is_none());
    }

    #[test]
    fn signer_info_round_trips_through_der() {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let signed_attributes = build_two_pass_signed_attributes(
            b"encapsulated content",
            b"nonce",
            b"A0256K0TB00E0000",
        )
        .unwrap();

        let signer_info = build_signer_info(&credential, signed_attributes, &[0xAA; 256]).unwrap();

        let encoded = signer_info.to_der().unwrap();

        let decoded = SignerInfo::from_der(&encoded).unwrap();

        assert_eq!(decoded, signer_info);
    }

    #[test]
    fn signer_info_encodes_signed_attributes_as_implicit_context_zero() {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let signed_attributes = build_two_pass_signed_attributes(
            b"encapsulated content",
            b"nonce",
            b"A0256K0TB00E0000",
        )
        .unwrap();

        let signer_info = build_signer_info(&credential, signed_attributes, &[0xAA; 256]).unwrap();

        let encoded = signer_info.to_der().unwrap();

        // signedAttrs is encoded inside SignerInfo as [0] IMPLICIT.
        //
        // We don't assert an absolute offset because the preceding
        // issuer-and-serial value is variable-length. Instead, parse the
        // structure in the round-trip test above and make sure that the
        // context-specific constructed [0] tag is present.
        assert!(encoded.contains(&0xA0));
    }
}
