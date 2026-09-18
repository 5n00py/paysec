use cms::content_info::{CmsVersion, ContentInfo};

use cms::revocation::RevocationInfoChoices;

use cms::signed_data::{
    DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData, SignerInfo, SignerInfos,
};

use der::asn1::{Any, OctetString};

use der::{Decode, Encode};

use crate::asn1::signer_info::sha256_algorithm_identifier;

use crate::oid::{ID_ENVELOPED_DATA, ID_SIGNED_DATA};

use crate::Tr34Error;

/// Construct the outer CMS SignedData for a TR-34 key token.
///
/// `encapsulated_content` must be the exact DER encoding of the
/// EnvelopedData that was used to construct the SignerInfo's
/// `messageDigest` signed attribute.
///
/// The certificates field is omitted because the KRD is expected to
/// already possess the bound KDH credential.
///
/// `crls` is represented as optional at this low-level CMS layer. A
/// complete TR-34 key-token operation is responsible for supplying the
/// required KDH CA revocation information.
pub(crate) fn build_key_token_signed_data(
    encapsulated_content: &[u8],
    signer_info: SignerInfo,
    crls: Option<RevocationInfoChoices>,
) -> Result<SignedData, Tr34Error> {
    let digest_algorithms =
        DigestAlgorithmIdentifiers::try_from(vec![sha256_algorithm_identifier()])?;

    let signer_infos = SignerInfos::try_from(vec![signer_info])?;

    Ok(SignedData {
        // RFC 5652 requires version 3 when eContentType is other than
        // id-data. TR-34 uses id-envelopedData here.
        version: CmsVersion::V3,

        digest_algorithms,

        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_ENVELOPED_DATA,

            // Important: these are the exact bytes whose SHA-256 digest
            // appears in the signed messageDigest attribute.
            econtent: Some(Any::encode_from(&OctetString::new(
                encapsulated_content.to_vec(),
            )?)?),
        },

        // CredKDH was established during binding and is therefore not
        // repeated in the key token.
        certificates: None,

        crls,

        signer_infos,
    })
}

/// Wrap CMS SignedData in the top-level ContentInfo used on the wire.
pub(crate) fn wrap_signed_data(signed_data: &SignedData) -> Result<ContentInfo, Tr34Error> {
    let signed_data_der = signed_data.to_der()?;

    Ok(ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use cms::signed_data::SignedData;

    use crate::asn1::signed_attributes::build_two_pass_signed_attributes;

    use crate::asn1::signer_info::{build_signer_info, sha256_algorithm_identifier};

    use crate::KdhCredential;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../../tests/fixtures/kdh-certificate.der");

    fn signer_info(encapsulated_content: &[u8]) -> SignerInfo {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let signed_attributes = build_two_pass_signed_attributes(
            encapsulated_content,
            b"0123456789ABCDEF",
            b"A0256K0TB00E0000",
        )
        .unwrap();

        build_signer_info(&credential, signed_attributes, &[0xAA; 256]).unwrap()
    }

    #[test]
    fn builds_outer_signed_data_for_enveloped_content() {
        let encapsulated_content = b"exact enveloped data DER";

        let signer_info = signer_info(encapsulated_content);

        let expected_signer_infos = SignerInfos::try_from(vec![signer_info.clone()]).unwrap();

        let expected_digest_algorithms =
            DigestAlgorithmIdentifiers::try_from(vec![sha256_algorithm_identifier()]).unwrap();

        let signed_data =
            build_key_token_signed_data(encapsulated_content, signer_info, None).unwrap();

        assert_eq!(signed_data.version, CmsVersion::V3);

        assert_eq!(signed_data.digest_algorithms, expected_digest_algorithms);

        assert_eq!(
            signed_data.encap_content_info.econtent_type,
            ID_ENVELOPED_DATA
        );

        assert_eq!(
            signed_data
                .encap_content_info
                .econtent
                .as_ref()
                .unwrap()
                .value(),
            encapsulated_content
        );

        assert!(signed_data.certificates.is_none());

        assert!(signed_data.crls.is_none());

        assert_eq!(signed_data.signer_infos, expected_signer_infos);
    }

    #[test]
    fn signed_data_round_trips_through_der() {
        let encapsulated_content = b"exact enveloped data DER";

        let signed_data = build_key_token_signed_data(
            encapsulated_content,
            signer_info(encapsulated_content),
            None,
        )
        .unwrap();

        let encoded = signed_data.to_der().unwrap();

        let decoded = SignedData::from_der(&encoded).unwrap();

        assert_eq!(decoded, signed_data);
    }

    #[test]
    fn wraps_signed_data_in_content_info() {
        let encapsulated_content = b"exact enveloped data DER";

        let signed_data = build_key_token_signed_data(
            encapsulated_content,
            signer_info(encapsulated_content),
            None,
        )
        .unwrap();

        let content_info = wrap_signed_data(&signed_data).unwrap();

        assert_eq!(content_info.content_type, ID_SIGNED_DATA);

        assert_eq!(
            content_info.content.to_der().unwrap(),
            signed_data.to_der().unwrap()
        );
    }

    #[test]
    fn content_info_round_trips_through_der() {
        let encapsulated_content = b"exact enveloped data DER";

        let signed_data = build_key_token_signed_data(
            encapsulated_content,
            signer_info(encapsulated_content),
            None,
        )
        .unwrap();

        let content_info = wrap_signed_data(&signed_data).unwrap();

        let encoded = content_info.to_der().unwrap();

        let decoded = ContentInfo::from_der(&encoded).unwrap();

        assert_eq!(decoded, content_info);
    }
}
