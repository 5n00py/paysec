use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum PinBlockError {
    InvalidPin,
    RandomSeedTooShort { minimum: usize, actual: usize },
    InvalidPinFieldLength { expected: usize, actual: usize },
    InvalidControlField { actual: u8 },
    InvalidDecodedPinLength { actual: usize },
    InvalidPinDigit,
    InvalidFiller,
    InvalidPan,
    InvalidPinBlockLength { expected: usize, actual: usize },
    InvalidIntermediateBlockLength { expected: usize, actual: usize },
    Hex(hex::FromHexError),
}

impl Display for PinBlockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPin => write!(
                f,
                "PIN BLOCK ISO 4 ERROR: PIN must be between 4 and 12 digits long"
            ),

            Self::RandomSeedTooShort { .. } => write!(
                f,
                "PIN BLOCK ISO 4 ERROR: Random seed must be at least 8 bytes long"
            ),

            Self::InvalidPinFieldLength { .. } => {
                write!(f, "PIN BLOCK ISO 4 ERROR: PIN field must be 16 bytes long")
            }

            Self::InvalidControlField { actual } => write!(
                f,
                "PIN BLOCK ISO 4 ERROR: PIN block is not ISO format 4: control field `{actual}`"
            ),

            Self::InvalidDecodedPinLength { actual } => write!(
                f,
                "PIN BLOCK ISO 4 ERROR: PIN length must be between 4 and 12: `{actual}`"
            ),

            Self::InvalidPinDigit => write!(f, "PIN BLOCK ISO 4 ERROR: PIN contains invalid digit"),

            Self::InvalidFiller => {
                write!(f, "PIN BLOCK ISO 4 ERROR: PIN block filler is incorrect")
            }

            Self::InvalidPan => write!(
                f,
                "PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long."
            ),

            Self::InvalidPinBlockLength { .. } => {
                write!(f, "PIN BLOCK ISO 4 ERROR: PIN block must be 16 bytes long")
            }

            Self::InvalidIntermediateBlockLength { .. } => write!(
                f,
                "PIN BLOCK ISO 4 ERROR: Intermediate block must be 16 bytes long"
            ),

            Self::Hex(error) => Display::fmt(error, f),
        }
    }
}

impl Error for PinBlockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hex(error) => Some(error),
            _ => None,
        }
    }
}

impl From<hex::FromHexError> for PinBlockError {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}

#[derive(Debug)]
pub enum PinBlockCryptoError<E> {
    PinBlock(PinBlockError),
    Crypto(E),
}

impl<E> Display for PinBlockCryptoError<E>
where
    E: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PinBlock(error) => Display::fmt(error, f),
            Self::Crypto(error) => Display::fmt(error, f),
        }
    }
}

impl<E> Error for PinBlockCryptoError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PinBlock(error) => Some(error),
            Self::Crypto(error) => Some(error),
        }
    }
}

impl<E> From<PinBlockError> for PinBlockCryptoError<E> {
    fn from(error: PinBlockError) -> Self {
        Self::PinBlock(error)
    }
}
