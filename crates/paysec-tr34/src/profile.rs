/// TR-34 encoding profile.
///
/// Profiles represent coherent interoperability behavior rather than
/// individual ASN.1 or encoding switches.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Tr34Profile {
    /// Standards-oriented TR-34 encoding.
    ///
    /// This follows the normative TR-34 ASN.1 definitions and the
    /// underlying CMS and PKCS specifications where informative examples
    /// disagree with them.
    #[default]
    Strict,

    /// Compatibility profile for the encoding family demonstrated by
    /// ASC X9 TR 34-2019 Annex B.
    ///
    /// Known cryptographic defects in published examples are not reproduced.
    /// In particular, AES-CBC still uses a 16-byte IV.
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

/// Internal encoding decisions associated with a public TR-34 profile.
pub(crate) struct EncodingPolicy {
    pub(crate) key_block_version: KeyBlockVersionEncoding,
    pub(crate) key_block_header: KeyBlockHeaderEncoding,
    pub(crate) encrypted_content_layout: EncryptedContentLayout,
    pub(crate) oaep_parameters: OaepParametersEncoding,
}

impl EncodingPolicy {
    pub(crate) const fn for_profile(profile: Tr34Profile) -> Self {
        match profile {
            Tr34Profile::Strict => Self {
                key_block_version: KeyBlockVersionEncoding::AnnexD,
                key_block_header: KeyBlockHeaderEncoding::BareOctetString,
                encrypted_content_layout: EncryptedContentLayout::Cms,
                oaep_parameters: OaepParametersEncoding::Pkcs1,
            },

            Tr34Profile::AnnexB2019 => Self {
                key_block_version: KeyBlockVersionEncoding::AnnexBSample,
                key_block_header: KeyBlockHeaderEncoding::DataAttribute,
                encrypted_content_layout: EncryptedContentLayout::AnnexB2019,
                oaep_parameters: OaepParametersEncoding::AnnexBSample,
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
    }
}
