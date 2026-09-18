use std::error::Error;
use std::fmt::{Display, Formatter};

/// Errors produced while constructing, parsing, validating, or serializing
/// TR-34 data.
#[derive(Debug)]
pub enum Tr34Error {
    /// ASN.1 DER processing failed.
    Der(der::Error),

    /// The supplied X.509 credential is not valid DER.
    InvalidCertificate(der::Error),

    /// The supplied X.509 certificate revocation list is not valid DER.
    InvalidCrl(der::Error),
}

impl Display for Tr34Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Der(error) => {
                write!(f, "ERROR TR-34: DER processing failed: {error}")
            }

            Self::InvalidCertificate(error) => {
                write!(f, "ERROR TR-34: Invalid X.509 certificate: {error}")
            }

            Self::InvalidCrl(error) => {
                write!(f, "ERROR TR-34: Invalid X.509 CRL: {error}")
            }
        }
    }
}

impl Error for Tr34Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Der(error) | Self::InvalidCertificate(error) | Self::InvalidCrl(error) => {
                Some(error)
            }
        }
    }
}

impl From<der::Error> for Tr34Error {
    fn from(error: der::Error) -> Self {
        Self::Der(error)
    }
}

/// Error returned by TR-34 operations that may invoke a cryptographic
/// provider.
#[derive(Debug)]
pub enum Tr34CryptoError<E> {
    /// TR-34 parsing, validation, formatting, or ASN.1 processing failed.
    Tr34(Tr34Error),

    /// The cryptographic provider reported an error.
    Crypto(E),
}

impl<E> Display for Tr34CryptoError<E>
where
    E: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tr34(error) => Display::fmt(error, f),
            Self::Crypto(error) => Display::fmt(error, f),
        }
    }
}

impl<E> Error for Tr34CryptoError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tr34(error) => Some(error),
            Self::Crypto(error) => Some(error),
        }
    }
}

impl<E> From<Tr34Error> for Tr34CryptoError<E> {
    fn from(error: Tr34Error) -> Self {
        Self::Tr34(error)
    }
}
