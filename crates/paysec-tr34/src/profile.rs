/// TR-34 encoding profile.
///
/// Profiles represent coherent interoperability behavior rather than
/// individual ASN.1 or encoding switches.
///
/// Additional compatibility profiles are added only when their complete
/// behavior is implemented and covered by interoperability tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Tr34Profile {
    /// Standards-oriented TR-34 encoding.
    ///
    /// This profile follows the normative TR-34 ASN.1 definitions and the
    /// underlying CMS and PKCS specifications where informative examples
    /// disagree with them.
    #[default]
    Strict,
}

/// Internal encoding decisions associated with a public TR-34 profile.
///
/// The public API exposes coherent profiles. Individual compatibility
/// decisions remain private so that future vendor and integration profiles
/// can compose the required behavior without exposing independent switches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncodingPolicy;

impl EncodingPolicy {
    pub(crate) const fn for_profile(profile: Tr34Profile) -> Self {
        match profile {
            Tr34Profile::Strict => Self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_resolves_to_encoding_policy() {
        assert_eq!(
            EncodingPolicy::for_profile(Tr34Profile::Strict),
            EncodingPolicy,
        );
    }
}
