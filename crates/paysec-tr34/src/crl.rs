use cms::revocation::RevocationInfoChoice;

use der::Decode;

use x509_cert::crl::CertificateList;

use crate::Tr34Error;

/// KDH CA certificate revocation list used in TR-34 messages.
///
/// Construction from DER only establishes that the input is a syntactically
/// valid X.509 CRL. It does not validate the CRL signature, freshness,
/// issuer, or other TR-34 profile requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KdhCrl {
    certificate_list: CertificateList,
}

impl KdhCrl {
    /// Parse a DER-encoded X.509 certificate revocation list.
    pub fn from_der(input: &[u8]) -> Result<Self, Tr34Error> {
        let certificate_list = CertificateList::from_der(input).map_err(Tr34Error::InvalidCrl)?;

        Ok(Self { certificate_list })
    }

    /// Construct from an already parsed X.509 certificate revocation list.
    pub const fn from_certificate_list(certificate_list: CertificateList) -> Self {
        Self { certificate_list }
    }

    /// Return the underlying X.509 certificate revocation list.
    pub const fn certificate_list(&self) -> &CertificateList {
        &self.certificate_list
    }

    /// Consume this value and return the underlying CRL.
    pub fn into_certificate_list(self) -> CertificateList {
        self.certificate_list
    }

    pub(crate) fn revocation_info_choice(&self) -> RevocationInfoChoice {
        RevocationInfoChoice::Crl(self.certificate_list.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    const KDH_CRL_DER: &[u8] = include_bytes!("../tests/fixtures/kdh-crl.der");

    #[test]
    fn parses_kdh_crl_from_der() {
        let crl = KdhCrl::from_der(KDH_CRL_DER).unwrap();

        assert_eq!(crl.certificate_list().to_der().unwrap(), KDH_CRL_DER);
    }

    #[test]
    fn rejects_invalid_kdh_crl_der() {
        let result = KdhCrl::from_der(b"not a crl");

        assert!(matches!(result, Err(Tr34Error::InvalidCrl(_))));
    }
}
