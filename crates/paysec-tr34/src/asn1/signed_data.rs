use cms::content_info::{CmsVersion, ContentInfo};

use cms::revocation::RevocationInfoChoices;

use cms::signed_data::{
    DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData, SignerInfo, SignerInfos,
};

use der::asn1::{Any, OctetString};

use der::{Decode, Encode};

use crate::profile::SignedDataVersionEncoding;

use crate::asn1::signed_attributes::encode_constructed;
use crate::asn1::signer_info::sha256_algorithm_identifier;

use crate::oid::{ID_ENVELOPED_DATA, ID_SIGNED_DATA};

use crate::{KdhCrl, Tr34Error};

fn signed_data_version(encoding: SignedDataVersionEncoding) -> CmsVersion {
    match encoding {
        SignedDataVersionEncoding::CmsV3 => CmsVersion::V3,
        SignedDataVersionEncoding::AnnexBSampleV1 => CmsVersion::V1,
    }
}

/// Construct the outer CMS SignedData for a TR-34 key token.
///
/// `encapsulated_content` must be the exact DER encoding of the
/// EnvelopedData that was used to construct the SignerInfo's
/// `messageDigest` signed attribute.
///
/// The certificates field is omitted because the KRD is expected to
/// already possess the bound KDH credential.
///
/// Strict TR-34 key transport includes CRLCA_KDH. This lower-level
/// constructor nevertheless allows the CRL to be omitted so that
/// compatibility encodings can be represented without changing the
/// CMS assembly layer.
pub(crate) fn build_key_token_signed_data(
    encapsulated_content: &[u8],
    signer_info: SignerInfo,
    kdh_crl: Option<&KdhCrl>,
) -> Result<SignedData, Tr34Error> {
    let digest_algorithms =
        DigestAlgorithmIdentifiers::try_from(vec![sha256_algorithm_identifier()])?;

    let signer_infos = SignerInfos::try_from(vec![signer_info])?;

    let crls = match kdh_crl {
        Some(kdh_crl) => Some(RevocationInfoChoices::try_from(vec![
            kdh_crl.revocation_info_choice(),
        ])?),

        None => None,
    };

    Ok(SignedData {
        version: CmsVersion::V3,

        digest_algorithms,

        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_ENVELOPED_DATA,

            econtent: Some(Any::encode_from(&OctetString::new(
                encapsulated_content.to_vec(),
            )?)?),
        },

        certificates: None,

        crls,

        signer_infos,
    })
}

/// Encode SignedData while preserving an already encoded SignerInfo.
///
/// This is used by compatibility paths whose SignerInfo cannot safely pass
/// through the normal CMS object model without changing its wire encoding.
///
/// `version` controls only the outer SignedData version encoding. The strict
/// structured path continues to derive and encode CMS version 3 normally.
pub(crate) fn encode_signed_data_with_signer_info_der(
    encapsulated_content: &[u8],
    signer_info_der: &[u8],
    kdh_crl: Option<&KdhCrl>,
    version: SignedDataVersionEncoding,
) -> Result<Vec<u8>, Tr34Error> {
    let digest_algorithms =
        DigestAlgorithmIdentifiers::try_from(vec![sha256_algorithm_identifier()])?.to_der()?;

    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: ID_ENVELOPED_DATA,

        econtent: Some(Any::encode_from(&OctetString::new(
            encapsulated_content.to_vec(),
        )?)?),
    }
    .to_der()?;

    let mut content = Vec::new();

    content.extend_from_slice(&signed_data_version(version).to_der()?);

    content.extend_from_slice(&digest_algorithms);

    content.extend_from_slice(&encap_content_info);

    if let Some(kdh_crl) = kdh_crl {
        let mut crls =
            RevocationInfoChoices::try_from(vec![kdh_crl.revocation_info_choice()])?.to_der()?;

        // RevocationInfoChoices is SET OF on its own, but SignedData
        // carries the same contents as [1] IMPLICIT.
        debug_assert_eq!(crls.first(), Some(&0x31),);

        crls[0] = 0xA1;

        content.extend_from_slice(&crls);
    }

    // SignerInfos is SET OF SignerInfo. There is exactly one signer in
    // the TR-34 key-token path.
    content.extend_from_slice(&encode_constructed(0x31, signer_info_der));

    Ok(encode_constructed(0x30, &content))
}

/// Wrap CMS SignedData in the top-level ContentInfo used on the wire.
pub(crate) fn wrap_signed_data(signed_data: &SignedData) -> Result<ContentInfo, Tr34Error> {
    let signed_data_der = signed_data.to_der()?;

    Ok(ContentInfo {
        content_type: ID_SIGNED_DATA,

        content: Any::from_der(&signed_data_der)?,
    })
}

/// Wrap an already encoded SignedData value in the top-level ContentInfo.
///
/// The supplied SignedData bytes are preserved exactly.
pub(crate) fn wrap_signed_data_der(signed_data_der: &[u8]) -> Result<ContentInfo, Tr34Error> {
    Ok(ContentInfo {
        content_type: ID_SIGNED_DATA,

        content: Any::from_der(signed_data_der)?,
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

    const KDH_CRL_DER: &[u8] = include_bytes!("../../tests/fixtures/kdh-crl.der");

    fn kdh_crl() -> KdhCrl {
        KdhCrl::from_der(KDH_CRL_DER).unwrap()
    }

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

        let kdh_crl = kdh_crl();

        let signed_data =
            build_key_token_signed_data(encapsulated_content, signer_info, Some(&kdh_crl)).unwrap();

        assert_eq!(signed_data.version, CmsVersion::V3,);

        assert_eq!(signed_data.digest_algorithms, expected_digest_algorithms,);

        assert_eq!(
            signed_data.encap_content_info.econtent_type,
            ID_ENVELOPED_DATA,
        );

        assert_eq!(
            signed_data
                .encap_content_info
                .econtent
                .as_ref()
                .unwrap()
                .value(),
            encapsulated_content,
        );

        assert!(signed_data.certificates.is_none(),);

        assert!(signed_data.crls.is_some(),);

        assert_eq!(signed_data.signer_infos, expected_signer_infos,);

        let crls = signed_data.crls.as_ref().unwrap();

        assert_eq!(crls.0.len(), 1,);

        match crls.0.get(0).unwrap() {
            cms::revocation::RevocationInfoChoice::Crl(crl) => {
                assert_eq!(crl.to_der().unwrap(), KDH_CRL_DER,);
            }

            other => {
                panic!("unexpected revocation information: {other:?}");
            }
        }
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

        assert_eq!(decoded, signed_data,);
    }

    #[test]
    fn raw_signed_data_encoder_matches_cms_for_canonical_signer_info() {
        let encapsulated_content = b"exact enveloped data DER";

        let signer_info = signer_info(encapsulated_content);

        let signer_info_der = signer_info.to_der().unwrap();

        let kdh_crl = kdh_crl();

        let expected =
            build_key_token_signed_data(encapsulated_content, signer_info, Some(&kdh_crl))
                .unwrap()
                .to_der()
                .unwrap();

        let actual = encode_signed_data_with_signer_info_der(
            encapsulated_content,
            &signer_info_der,
            Some(&kdh_crl),
            SignedDataVersionEncoding::CmsV3,
        )
        .unwrap();

        assert_eq!(actual, expected,);
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

        assert_eq!(content_info.content_type, ID_SIGNED_DATA,);

        assert_eq!(
            content_info.content.to_der().unwrap(),
            signed_data.to_der().unwrap(),
        );
    }

    #[test]
    fn raw_signed_data_wrapper_matches_structured_wrapper() {
        let encapsulated_content = b"exact enveloped data DER";

        let signed_data = build_key_token_signed_data(
            encapsulated_content,
            signer_info(encapsulated_content),
            None,
        )
        .unwrap();

        let signed_data_der = signed_data.to_der().unwrap();

        let structured = wrap_signed_data(&signed_data).unwrap().to_der().unwrap();

        let raw = wrap_signed_data_der(&signed_data_der)
            .unwrap()
            .to_der()
            .unwrap();

        assert_eq!(raw, structured,);
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

        assert_eq!(decoded, content_info,);
    }

    #[test]
    fn raw_signed_data_can_encode_annex_b_version_one() {
        let encapsulated_content = b"exact enveloped data DER";

        let signer_info = signer_info(encapsulated_content);

        let signer_info_der = signer_info.to_der().unwrap();

        let encoded = encode_signed_data_with_signer_info_der(
            encapsulated_content,
            &signer_info_der,
            None,
            SignedDataVersionEncoding::AnnexBSampleV1,
        )
        .unwrap();

        let decoded = SignedData::from_der(&encoded).unwrap();

        assert_eq!(decoded.version, CmsVersion::V1,);
    }
}
