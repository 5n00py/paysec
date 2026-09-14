use std::{error::Error, fmt};

use paysec_crypto::AesKeySize;

/// Errors returned by AES DUKPT operations.
#[derive(Debug)]
pub enum DukptError<E> {
    /// The cryptographic provider failed.
    Crypto(E),

    /// The requested working key is stronger than the derivation key.
    WorkingKeyTooStrong {
        derivation_key_size: AesKeySize,
        working_key_size: AesKeySize,
    },
}

impl<E> fmt::Display for DukptError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => {
                write!(f, "cryptographic provider error: {error}")
            }

            Self::WorkingKeyTooStrong {
                derivation_key_size,
                working_key_size,
            } => {
                write!(
                    f,
                    "working key strength exceeds derivation key strength \
                     (derivation key: {} bits, working key: {} bits)",
                    derivation_key_size.bytes() * 8,
                    working_key_size.bytes() * 8,
                )
            }
        }
    }
}

impl<E> Error for DukptError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),

            Self::WorkingKeyTooStrong { .. } => None,
        }
    }
}
