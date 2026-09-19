use cms::signed_data::SignedAttributes;

use der::Encode;
use der::asn1::{Any, OctetString, SetOfVec};

use sha2::{Digest, Sha256};

use spki::ObjectIdentifier;

use x509_cert::attr::Attribute;

use crate::oid::{ID_CONTENT_TYPE, ID_DATA, ID_ENVELOPED_DATA, ID_MESSAGE_DIGEST, ID_RANDOM_NONCE};

use crate::Tr34Error;

/// SignedAttributes encoded in the two forms needed by CMS signing.
///
/// `signing_der` uses the normal SET OF tag (`0x31`) because those are the
/// bytes covered by the signature.
///
/// `signer_info_der` uses the `[0] IMPLICIT` tag (`0xA0`) used when the same
/// attribute contents are embedded in SignerInfo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncodedSignedAttributes {
    signing_der: Vec<u8>,
    signer_info_der: Vec<u8>,
}

impl EncodedSignedAttributes {
    pub(crate) fn signing_der(&self) -> &[u8] {
        &self.signing_der
    }

    pub(crate) fn signer_info_der(&self) -> &[u8] {
        &self.signer_info_der
    }
}

/// Construct the strict two-pass TR-34 SignedAttributes.
///
/// `encapsulated_content` must be the exact DER bytes of the EnvelopedData
/// that will be placed in the outer SignedData `eContent`.
///
/// The attributes contain:
///
/// - contentType = id-envelopedData
/// - randomNonce = RKRD
/// - id-data = clear Key Block Header
/// - messageDigest = SHA-256(encapsulated_content)
///
/// The resulting `SET OF` is DER-canonicalized independently of the order
/// in which the attributes are supplied here.
pub(crate) fn build_two_pass_signed_attributes(
    encapsulated_content: &[u8],
    random_nonce: &[u8],
    key_block_header: &[u8],
) -> Result<SignedAttributes, Tr34Error> {
    let message_digest: [u8; 32] = Sha256::digest(encapsulated_content).into();

    build_two_pass_signed_attributes_from_digest(random_nonce, key_block_header, &message_digest)
}

/// Encode SignedAttributes in the form covered by the CMS signature.
///
/// Although `signedAttrs` appears in SignerInfo as `[0] IMPLICIT`, CMS
/// signatures are calculated over the complete DER encoding of the
/// SignedAttributes value using its normal SET OF tag.
pub(crate) fn signed_attributes_signing_der(
    signed_attributes: &SignedAttributes,
) -> Result<Vec<u8>, Tr34Error> {
    Ok(signed_attributes.to_der()?)
}

/// Encode two-pass SignedAttributes using the order published in the
/// TR-34 2019 Annex B samples.
///
/// Unlike the strict path, these bytes deliberately do not pass through
/// `SignedAttributes`, because DER SET OF canonicalization would reorder
/// the attributes.
///
/// The preserved order is:
///
/// 1. contentType
/// 2. randomNonce
/// 3. id-data / Key Block Header
/// 4. messageDigest
pub(crate) fn encode_annex_b_two_pass_signed_attributes(
    encapsulated_content: &[u8],
    random_nonce: &[u8],
    key_block_header: &[u8],
) -> Result<EncodedSignedAttributes, Tr34Error> {
    let message_digest: [u8; 32] = Sha256::digest(encapsulated_content).into();

    encode_annex_b_two_pass_signed_attributes_from_digest(
        random_nonce,
        key_block_header,
        &message_digest,
    )
}

fn build_two_pass_signed_attributes_from_digest(
    random_nonce: &[u8],
    key_block_header: &[u8],
    message_digest: &[u8; 32],
) -> Result<SignedAttributes, Tr34Error> {
    Ok(SignedAttributes::try_from(
        build_two_pass_attributes_from_digest(random_nonce, key_block_header, message_digest)?,
    )?)
}

fn encode_annex_b_two_pass_signed_attributes_from_digest(
    random_nonce: &[u8],
    key_block_header: &[u8],
    message_digest: &[u8; 32],
) -> Result<EncodedSignedAttributes, Tr34Error> {
    let attributes =
        build_two_pass_attributes_from_digest(random_nonce, key_block_header, message_digest)?;

    let mut content = Vec::new();

    for attribute in attributes {
        content.extend_from_slice(&attribute.to_der()?);
    }

    Ok(EncodedSignedAttributes {
        signing_der: encode_constructed(0x31, &content),

        signer_info_der: encode_constructed(0xA0, &content),
    })
}

fn build_two_pass_attributes_from_digest(
    random_nonce: &[u8],
    key_block_header: &[u8],
    message_digest: &[u8; 32],
) -> Result<Vec<Attribute>, Tr34Error> {
    let content_type =
        single_value_attribute(ID_CONTENT_TYPE, Any::encode_from(&ID_ENVELOPED_DATA)?)?;

    let random_nonce = OctetString::new(random_nonce.to_vec())?;

    let random_nonce = single_value_attribute(ID_RANDOM_NONCE, Any::encode_from(&random_nonce)?)?;

    let key_block_header = OctetString::new(key_block_header.to_vec())?;

    let key_block_header = single_value_attribute(ID_DATA, Any::encode_from(&key_block_header)?)?;

    let message_digest = OctetString::new(message_digest.to_vec())?;

    let message_digest =
        single_value_attribute(ID_MESSAGE_DIGEST, Any::encode_from(&message_digest)?)?;

    Ok(vec![
        content_type,
        random_nonce,
        key_block_header,
        message_digest,
    ])
}

fn single_value_attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute, Tr34Error> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value])?,
    })
}

/// Encode a constructed ASN.1 value around already encoded content.
///
/// This is used by the compatibility path where the contents must remain
/// byte-for-byte in their supplied order rather than being represented by
/// a DER SET OF collection.
pub(crate) fn encode_constructed(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(content.len() + 8);

    encoded.push(tag);

    encode_der_length(content.len(), &mut encoded);

    encoded.extend_from_slice(content);

    encoded
}

fn encode_der_length(length: usize, output: &mut Vec<u8>) {
    if length < 128 {
        output.push(length as u8);
        return;
    }

    let bytes = length.to_be_bytes();

    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero DER length");

    let bytes = &bytes[first..];

    output.push(0x80 | bytes.len() as u8);

    output.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_strict_two_pass_signed_attributes_in_der_order() {
        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let message_digest: [u8; 32] = hex::decode(
            "5D98145E22FCB7F6751B1A453A30C524\
                 87F924BC75EF46DB7974C7AA6C4BC72D",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let signed_attributes = build_two_pass_signed_attributes_from_digest(
            &random_nonce,
            b"A0256K0TB00E0000",
            &message_digest,
        )
        .unwrap();

        let encoded = signed_attributes_signing_der(&signed_attributes).unwrap();

        let expected = hex::decode(
            "31818E\
                 3018\
                 06092A864886F70D010903\
                 310B\
                 06092A864886F70D010703\
                 301F\
                 06092A864886F70D010701\
                 3112\
                 041041303235364B30544230304530303030\
                 3020\
                 060A2A864886F70D01091903\
                 3112\
                 0410167EB0E72781E4940112233445566778\
                 302F\
                 06092A864886F70D010904\
                 3122\
                 04205D98145E22FCB7F6751B1A453A30C524\
                 87F924BC75EF46DB7974C7AA6C4BC72D",
        )
        .unwrap();

        assert_eq!(encoded, expected,);
    }

    #[test]
    fn annex_b_signed_attributes_preserve_sample_order() {
        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let message_digest: [u8; 32] = hex::decode(
            "5D98145E22FCB7F6751B1A453A30C524\
                 87F924BC75EF46DB7974C7AA6C4BC72D",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let encoded = encode_annex_b_two_pass_signed_attributes_from_digest(
            &random_nonce,
            b"A0256K0TB00E0000",
            &message_digest,
        )
        .unwrap();

        let expected = hex::decode(
            "31818E\
                 3018\
                 06092A864886F70D010903\
                 310B\
                 06092A864886F70D010703\
                 3020\
                 060A2A864886F70D01091903\
                 3112\
                 0410167EB0E72781E4940112233445566778\
                 301F\
                 06092A864886F70D010701\
                 3112\
                 041041303235364B30544230304530303030\
                 302F\
                 06092A864886F70D010904\
                 3122\
                 04205D98145E22FCB7F6751B1A453A30C524\
                 87F924BC75EF46DB7974C7AA6C4BC72D",
        )
        .unwrap();

        assert_eq!(encoded.signing_der(), expected.as_slice(),);

        let mut expected_signer_info = expected.clone();

        expected_signer_info[0] = 0xA0;

        assert_eq!(encoded.signer_info_der(), expected_signer_info.as_slice(),);
    }

    #[test]
    fn computes_message_digest_over_exact_encapsulated_content() {
        let expected_digest: [u8; 32] = hex::decode(
            "BA7816BF8F01CFEA414140DE5DAE2223\
                 B00361A396177A9CB410FF61F20015AD",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let actual = build_two_pass_signed_attributes(b"abc", b"nonce", b"header").unwrap();

        let expected =
            build_two_pass_signed_attributes_from_digest(b"nonce", b"header", &expected_digest)
                .unwrap();

        assert_eq!(actual, expected,);
    }

    #[test]
    fn signing_der_uses_set_of_tag() {
        let signed_attributes =
            build_two_pass_signed_attributes(b"encapsulated content", b"nonce", b"header").unwrap();

        let encoded = signed_attributes_signing_der(&signed_attributes).unwrap();

        // SignerInfo encodes signedAttrs as [0] IMPLICIT, but the
        // signature itself covers the normal DER SET OF encoding.
        assert_eq!(encoded[0], 0x31,);
    }

    #[test]
    fn annex_b_signing_and_signer_info_encodings_differ_only_by_tag() {
        let encoded =
            encode_annex_b_two_pass_signed_attributes(b"encapsulated content", b"nonce", b"header")
                .unwrap();

        assert_eq!(encoded.signing_der()[0], 0x31,);

        assert_eq!(encoded.signer_info_der()[0], 0xA0,);

        assert_eq!(&encoded.signing_der()[1..], &encoded.signer_info_der()[1..],);
    }

    #[test]
    fn signed_attributes_are_canonically_ordered() {
        let random_nonce = hex::decode("167EB0E72781E4940112233445566778").unwrap();

        let message_digest = [0x42; 32];

        let signed_attributes = build_two_pass_signed_attributes_from_digest(
            &random_nonce,
            b"A0256K0TB00E0000",
            &message_digest,
        )
        .unwrap();

        let oids: Vec<_> = signed_attributes
            .iter()
            .map(|attribute| attribute.oid)
            .collect();

        assert_eq!(
            oids,
            vec![ID_CONTENT_TYPE, ID_DATA, ID_RANDOM_NONCE, ID_MESSAGE_DIGEST,],
        );
    }
}
