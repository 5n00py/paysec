use cms::cert::IssuerAndSerialNumber;
use cms::enveloped_data::RecipientIdentifier;

use der::{Decode, Encode};

use x509_cert::Certificate;

use crate::Error;

fn parse_certificate(input: &[u8]) -> Result<Certificate, Error> {
    Certificate::from_der(input).map_err(Error::InvalidCertificate)
}

fn issuer_and_serial_number(certificate: &Certificate) -> IssuerAndSerialNumber {
    IssuerAndSerialNumber {
        issuer: certificate.tbs_certificate.issuer.clone(),
        serial_number: certificate.tbs_certificate.serial_number.clone(),
    }
}

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
        Ok(Self {
            certificate: parse_certificate(input)?,
        })
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

    pub(crate) fn issuer_and_serial_number(&self) -> IssuerAndSerialNumber {
        issuer_and_serial_number(&self.certificate)
    }
}

/// KRD X.509 credential used by TR-34.
///
/// Construction from DER parses the certificate structure only. It does not
/// perform certificate-path, revocation, validity, key-usage, or TR-34
/// profile validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KrdCredential {
    certificate: Certificate,
}

impl KrdCredential {
    /// Parse a DER-encoded KRD certificate.
    pub fn from_der(input: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            certificate: parse_certificate(input)?,
        })
    }

    /// Construct a KRD credential from an already parsed certificate.
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

    /// Return the DER-encoded SubjectPublicKeyInfo containing the KRD public
    /// key.
    ///
    /// The returned value is provider-neutral. A concrete cryptographic
    /// provider may import or otherwise consume this representation.
    pub fn subject_public_key_info_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()?)
    }

    pub(crate) fn issuer_and_serial_number(&self) -> IssuerAndSerialNumber {
        issuer_and_serial_number(&self.certificate)
    }

    pub(crate) fn recipient_identifier(&self) -> RecipientIdentifier {
        RecipientIdentifier::IssuerAndSerialNumber(self.issuer_and_serial_number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../tests/fixtures/kdh-certificate.der");

    const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("../tests/fixtures/krd-certificate.der");

    #[test]
    fn kdh_identifier_uses_certificate_issuer_and_serial_number() {
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

    #[test]
    fn krd_identifier_uses_certificate_issuer_and_serial_number() {
        let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

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

    #[test]
    fn krd_recipient_identifier_uses_issuer_and_serial_number() {
        let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let recipient_identifier = credential.recipient_identifier();

        assert_eq!(
            recipient_identifier,
            RecipientIdentifier::IssuerAndSerialNumber(credential.issuer_and_serial_number())
        );
    }

    #[test]
    fn krd_subject_public_key_info_is_der_encodable() {
        let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let encoded = credential.subject_public_key_info_der().unwrap();

        assert!(!encoded.is_empty());
    }
}
