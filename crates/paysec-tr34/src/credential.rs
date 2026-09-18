use cms::cert::IssuerAndSerialNumber;
use der::Decode;
use x509_cert::Certificate;

use crate::Error;

/// KDH X.509 credential used by TR-34.
///
/// Construction from DER parses the certificate structure only. It does not
/// perform certificate-path, revocation, validity, or TR-34 profile
/// validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KdhCredential {
    certificate: Certificate,
}

impl KdhCredential {
    /// Parse a DER-encoded KDH certificate.
    pub fn from_der(input: &[u8]) -> Result<Self, Error> {
        let certificate = Certificate::from_der(input).map_err(Error::InvalidCertificate)?;

        Ok(Self { certificate })
    }

    /// Construct a KDH credential from an already parsed certificate.
    pub const fn from_certificate(certificate: Certificate) -> Self {
        Self { certificate }
    }

    /// Return the underlying X.509 certificate.
    pub const fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Consume this credential and return the underlying certificate.
    pub fn into_certificate(self) -> Certificate {
        self.certificate
    }

    /// Return the CMS issuer-and-serial-number identifier for this
    /// credential.
    pub(crate) fn issuer_and_serial_number(&self) -> IssuerAndSerialNumber {
        IssuerAndSerialNumber {
            issuer: self.certificate.tbs_certificate.issuer.clone(),
            serial_number: self.certificate.tbs_certificate.serial_number.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../tests/fixtures/kdh-certificate.der");

    #[test]
    fn derives_identifier_from_certificate_issuer_and_serial_number() {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let identifier = credential.issuer_and_serial_number();

        assert_eq!(
            identifier.issuer,
            credential.certificate().tbs_certificate.issuer
        );

        assert_eq!(
            identifier.serial_number,
            credential.certificate().tbs_certificate.serial_number
        );
    }
}
