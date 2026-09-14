use std::{error::Error, fmt};

/// Errors returned by AES DUKPT operations.
#[derive(Debug)]
pub enum DukptError<E> {
    /// The cryptographic provider failed.
    Crypto(E),
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
        }
    }
}
