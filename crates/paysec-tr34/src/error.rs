use std::error::Error as StdError;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Der(der::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Der(error) => write!(f, "DER error: {error}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Der(error) => Some(error),
        }
    }
}

impl From<der::Error> for Error {
    fn from(error: der::Error) -> Self {
        Self::Der(error)
    }
}
