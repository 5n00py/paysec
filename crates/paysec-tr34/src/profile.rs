/// Encoding profile used when producing TR-34 data.
///
/// `Strict` follows the normative ASN.1/CMS encoding used by this crate.
///
/// `AnnexB2019` reproduces the coherent compatibility conventions found in
/// the TR-34 2019 Annex B samples where those conventions differ from the
/// normative encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Tr34Profile {
    Strict,
    AnnexB2019,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyBlockVersionEncoding {
    AnnexD,
    AnnexBSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyBlockHeaderEncoding {
    BareOctetString,
    DataAttribute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncryptedContentLayout {
    Cms,
    AnnexB2019,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OaepParametersEncoding {
    Pkcs1,
    AnnexBSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignedAttributesOrder {
    Der,
    AnnexBSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignatureAlgorithmEncoding {
    Sha256WithRsaEncryption,
    RsaEncryption,
}

/// Private decomposition of the public TR-34 encoding profiles.
///
/// Keeping the individual compatibility choices private allows public
/// profiles to remain coherent while preventing callers from constructing
/// arbitrary combinations of encoding quirks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncodingPolicy {
    pub(crate) key_block_version: KeyBlockVersionEncoding,
    pub(crate) key_block_header: KeyBlockHeaderEncoding,
    pub(crate) encrypted_content_layout: EncryptedContentLayout,
    pub(crate) oaep_parameters: OaepParametersEncoding,
    pub(crate) signed_attributes_order: SignedAttributesOrder,
    pub(crate) signature_algorithm: SignatureAlgorithmEncoding,
}

impl EncodingPolicy {
    pub(crate) const fn for_profile(profile: Tr34Profile) -> Self {
        match profile {
            Tr34Profile::Strict => Self {
                key_block_version: KeyBlockVersionEncoding::AnnexD,
                key_block_header: KeyBlockHeaderEncoding::BareOctetString,
                encrypted_content_layout: EncryptedContentLayout::Cms,
                oaep_parameters: OaepParametersEncoding::Pkcs1,
                signed_attributes_order: SignedAttributesOrder::Der,
                signature_algorithm: SignatureAlgorithmEncoding::Sha256WithRsaEncryption,
            },

            Tr34Profile::AnnexB2019 => Self {
                key_block_version: KeyBlockVersionEncoding::AnnexBSample,
                key_block_header: KeyBlockHeaderEncoding::DataAttribute,
                encrypted_content_layout: EncryptedContentLayout::AnnexB2019,
                oaep_parameters: OaepParametersEncoding::AnnexBSample,
                signed_attributes_order: SignedAttributesOrder::AnnexBSample,
                signature_algorithm: SignatureAlgorithmEncoding::RsaEncryption,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_uses_normative_key_block_encoding() {
        let policy = EncodingPolicy::for_profile(Tr34Profile::Strict);

        assert_eq!(policy.key_block_version, KeyBlockVersionEncoding::AnnexD,);

        assert_eq!(
            policy.key_block_header,
            KeyBlockHeaderEncoding::BareOctetString,
        );

        assert_eq!(policy.encrypted_content_layout, EncryptedContentLayout::Cms,);

        assert_eq!(policy.oaep_parameters, OaepParametersEncoding::Pkcs1,);

        assert_eq!(policy.signed_attributes_order, SignedAttributesOrder::Der,);

        assert_eq!(
            policy.signature_algorithm,
            SignatureAlgorithmEncoding::Sha256WithRsaEncryption,
        );
    }

    #[test]
    fn annex_b_profile_uses_sample_key_block_encoding() {
        let policy = EncodingPolicy::for_profile(Tr34Profile::AnnexB2019);

        assert_eq!(
            policy.key_block_version,
            KeyBlockVersionEncoding::AnnexBSample,
        );

        assert_eq!(
            policy.key_block_header,
            KeyBlockHeaderEncoding::DataAttribute,
        );

        assert_eq!(
            policy.encrypted_content_layout,
            EncryptedContentLayout::AnnexB2019,
        );

        assert_eq!(policy.oaep_parameters, OaepParametersEncoding::AnnexBSample,);

        assert_eq!(
            policy.signed_attributes_order,
            SignedAttributesOrder::AnnexBSample,
        );
    }
}
