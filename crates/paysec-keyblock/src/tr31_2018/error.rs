use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;

/// Errors produced while constructing or parsing a TR-31 payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// The cipher block length must be greater than zero.
    InvalidCipherBlockLength,

    /// The calculated payload length is invalid.
    InvalidTotalPayloadLength,

    /// The protected key is too large for the TR-31 16-bit key-length field.
    KeyTooLong { max: usize, actual: usize },

    /// The supplied random seed does not contain enough bytes for padding.
    RandomSeedTooShort { required: usize, actual: usize },

    /// The payload does not contain the two-byte key-length field.
    PayloadTooShort { minimum: usize, actual: usize },

    /// The payload does not contain as many key bytes as its length field
    /// declares.
    PayloadTooShortForKey { required: usize, actual: usize },
}

impl Display for PayloadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCipherBlockLength => write!(
                f,
                "ERROR TR-31 PAYLOAD: Cipher block length must be greater than zero"
            ),

            Self::InvalidTotalPayloadLength => {
                write!(f, "ERROR TR-31 PAYLOAD: Invalid total payload length")
            }

            Self::KeyTooLong { .. } => write!(
                f,
                "ERROR TR-31 PAYLOAD: Key length exceeds maximum representable length"
            ),

            Self::RandomSeedTooShort { .. } => write!(
                f,
                "ERROR TR-31 PAYLOAD: The provided random seed is too short for the padding requirement"
            ),

            Self::PayloadTooShort { .. } => write!(
                f,
                "ERROR TR-31 PAYLOAD: Payload too short to contain valid key length"
            ),

            Self::PayloadTooShortForKey { .. } => write!(
                f,
                "ERROR TR-31 PAYLOAD: Payload too short for the specified key length"
            ),
        }
    }
}

impl Error for PayloadError {}

/// Errors produced while constructing, parsing, or serializing TR-31
/// optional blocks.
#[derive(Debug)]
pub enum OptBlockError {
    /// The supplied optional-block string does not contain the minimum
    /// ID and length fields.
    StringTooShort { minimum: usize, actual: usize },

    /// Optional blocks are defined using ASCII data and cannot safely be
    /// parsed from arbitrary UTF-8 strings.
    NonAsciiInput,

    /// An extended-length optional block must contain at least 256 bytes.
    ExtendedLengthStringTooShort { minimum: usize, actual: usize },

    /// The encoded optional-block length exceeds the available input.
    StringTooShortForLength { required: usize, actual: usize },

    /// An optional block has not been initialized sufficiently for export.
    Uninitialized { length: usize },

    /// The optional-block identifier is not supported.
    InvalidId(String),

    /// Data was assigned before an optional-block identifier.
    IdNotSet,

    /// Optional-block data contains non-ASCII characters.
    NonAsciiData(String),

    /// The complete optional block exceeds the maximum representable size.
    BlockTooLong { maximum: usize, actual: usize },

    /// A normal length field must consist of exactly two hexadecimal
    /// characters.
    InvalidLengthFieldWidth { value: String, expected: usize },

    /// A normal length field is not valid hexadecimal.
    InvalidLengthFieldHex {
        value: String,
        source: ParseIntError,
    },

    /// A normal optional-block length cannot be smaller than four bytes.
    LengthFieldTooSmall { minimum: usize, actual: usize },

    /// An extended length field must consist of exactly six characters.
    InvalidExtendedLengthField(String),

    /// The first two characters of the extended length field must encode
    /// the supported length-of-length value.
    InvalidLengthOfLengthField(String),

    /// The extended block length is not valid hexadecimal.
    InvalidExtendedLengthHex {
        value: String,
        source: ParseIntError,
    },

    /// Extended encoding may only be used for block lengths greater than
    /// 255 bytes.
    ExtendedLengthTooSmall { value: String },
}

impl Display for OptBlockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StringTooShort { .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: String too short. Expected at least 4 characters"
            ),

            Self::NonAsciiInput => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Input contains non ASCII characters"
            ),

            Self::ExtendedLengthStringTooShort { .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: String containing extended length too short. Expected at least 256 characters"
            ),

            Self::StringTooShortForLength { required, .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: String too short for given length. Expected at least {} characters.",
                required
            ),

            Self::Uninitialized { .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Length must be greater than 4, indicating uninitialized OptBlock"
            ),

            Self::InvalidId(id) => write!(f, "ERROR TR-31 OPT BLOCK: Invalid ID: {}", id),

            Self::IdNotSet => write!(
                f,
                "ERROR TR-31 OPT BLOCK: ID not set (has to be set before data)"
            ),

            Self::NonAsciiData(data) => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Data has non ASCII characters: {}",
                data
            ),

            Self::BlockTooLong { actual, .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Block size '{}' is too long (must be max. 65535)",
                actual
            ),

            Self::InvalidLengthFieldWidth { value, .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Invalid length field: Expected a string with 2 characters, found '{}'",
                value
            ),

            Self::InvalidLengthFieldHex { value, .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Invalid length field: '{}' is not a valid hexadecimal number",
                value
            ),

            Self::LengthFieldTooSmall { actual, .. } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Invalid length field: value {} is too small (must be at least 4)",
                actual
            ),

            Self::InvalidExtendedLengthField(value) => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Invalid extended length field: {}",
                value
            ),

            Self::InvalidLengthOfLengthField(value) => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Invalid length of length field: {}",
                value
            ),

            Self::InvalidExtendedLengthHex { source, .. } => {
                // Preserve the previous behavior of exposing the underlying
                // hexadecimal parser message.
                Display::fmt(source, f)
            }

            Self::ExtendedLengthTooSmall { value } => write!(
                f,
                "ERROR TR-31 OPT BLOCK: Extended length is not greater than 255: {}",
                value
            ),
        }
    }
}

impl Error for OptBlockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidLengthFieldHex { source, .. }
            | Self::InvalidExtendedLengthHex { source, .. } => Some(source),

            _ => None,
        }
    }
}

/// Errors produced while constructing, parsing, validating, or serializing
/// a TR-31 key block header.
#[derive(Debug)]
pub enum KeyBlockHeaderError {
    InvalidDataLength {
        minimum: usize,
        actual: usize,
    },

    NonAsciiHeader,

    InvalidKeyBlockLength,

    InvalidNumberOfOptionalBlocks,

    InvalidHeaderLengthWithOptionalBlocks {
        minimum: usize,
        actual: usize,
    },

    InvalidVersionId(String),

    InvalidKeyUsage(String),

    InvalidAlgorithm(String),

    InvalidModeOfUse(String),

    InvalidKeyVersionNumberLength(String),

    InvalidKeyVersionNumberEncoding(String),

    InvalidExportability(String),

    TooManyOptionalBlocks {
        maximum: u8,
        actual: u8,
    },

    InvalidReservedField(String),

    ExportFailedEmptyFields,

    /// Error propagated directly from optional-block processing.
    OptionalBlock(OptBlockError),

    /// Optional-block error specifically encountered while parsing a header.
    FailedToParseOptionalBlocks(OptBlockError),
}

impl Display for KeyBlockHeaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDataLength { .. } => write!(f, "ERROR TR-31 HEADER: Invalid data length"),

            Self::NonAsciiHeader => write!(
                f,
                "ERROR TR-31 HEADER: Header contains non ASCII characters"
            ),

            Self::InvalidKeyBlockLength => {
                write!(f, "ERROR TR-31 HEADER: Invalid key block length")
            }

            Self::InvalidNumberOfOptionalBlocks => {
                write!(f, "ERROR TR-31 HEADER: Invalid number of optional blocks")
            }

            Self::InvalidHeaderLengthWithOptionalBlocks { .. } => write!(
                f,
                "ERROR TR-31 HEADER: Invalid header length containing optional blocks"
            ),

            Self::InvalidVersionId(value) => {
                write!(f, "ERROR TR-31 HEADER: Invalid version ID: {}", value)
            }

            Self::InvalidKeyUsage(value) => {
                write!(f, "ERROR TR-31 HEADER: Invalid key usage: {}", value)
            }

            Self::InvalidAlgorithm(value) => {
                write!(f, "ERROR TR-31 HEADER: Invalid algorithm: {}", value)
            }

            Self::InvalidModeOfUse(value) => {
                write!(f, "ERROR TR-31 HEADER: Invalid mode of use: {}", value)
            }

            Self::InvalidKeyVersionNumberLength(value) => write!(
                f,
                "ERROR TR-31 HEADER: Key version number must consist of 2 ASCII characters: {}",
                value
            ),

            Self::InvalidKeyVersionNumberEncoding(value) => write!(
                f,
                "ERROR TR-31 HEADER: Key version number must consist of ASCII characters: {}",
                value
            ),

            Self::InvalidExportability(value) => {
                write!(f, "ERROR TR-31 HEADER: Invalid exportability: {}", value)
            }

            Self::TooManyOptionalBlocks { .. } => write!(
                f,
                "ERROR TR-31 HEADER: Number of opt blocks value is too large"
            ),

            Self::InvalidReservedField(value) => write!(
                f,
                "ERROR TR-31 HEADER: Invalid value for reserved field: {}",
                value
            ),

            Self::ExportFailedEmptyFields => write!(
                f,
                "ERROR TR-31 HEADER: Export failed due to empty field(s) or zero length"
            ),

            Self::OptionalBlock(error) => Display::fmt(error, f),

            Self::FailedToParseOptionalBlocks(error) => write!(
                f,
                "ERROR TR-31 HEADER: Failed to parse optional blocks: {}",
                error
            ),
        }
    }
}

impl Error for KeyBlockHeaderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OptionalBlock(error) | Self::FailedToParseOptionalBlocks(error) => Some(error),

            _ => None,
        }
    }
}

impl From<OptBlockError> for KeyBlockHeaderError {
    fn from(error: OptBlockError) -> Self {
        Self::OptionalBlock(error)
    }
}

/// Errors produced by TR-31 key block processing.
#[derive(Debug)]
pub enum Tr31Error {
    /// The requested key block version is not supported by this
    /// implementation.
    UnsupportedVersion(String),

    /// The complete key block length is not aligned to the cipher block size.
    TotalBlockLengthNotMultiple {
        block_length: usize,
        actual: usize,
    },

    /// The actual key block length differs from the value encoded in the
    /// header.
    KeyBlockLengthMismatch {
        expected: usize,
        actual: usize,
    },

    /// The key block is shorter than the minimum valid version D block.
    KeyBlockBelowMinimum {
        minimum: usize,
        actual: usize,
    },

    /// The decoded MAC does not have the required length.
    InvalidMacLength {
        expected: usize,
        actual: usize,
    },

    /// Key block authentication failed.
    MacVerificationFailed,

    /// Header processing failed.
    Header(KeyBlockHeaderError),

    /// Payload processing failed.
    Payload(PayloadError),

    /// Hexadecimal decoding failed.
    Hex(hex::FromHexError),

    KeyBlockLengthTooLarge {
        maximum: usize,
        actual: usize,
    },
}

impl Display for Tr31Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(
                f,
                "ERROR TR-31: Key block version not supported by implementation: {}",
                version
            ),

            Self::TotalBlockLengthNotMultiple { block_length, .. } => write!(
                f,
                "ERROR TR-31: Total block length is not a multiple of block length: {}",
                block_length
            ),

            Self::KeyBlockLengthMismatch { .. } => write!(
                f,
                "ERROR TR-31: Key block length does not match its length in the header"
            ),

            Self::KeyBlockBelowMinimum { .. } => write!(
                f,
                "ERROR TR-31: Key block length is below minimum required length"
            ),

            Self::InvalidMacLength { expected, actual } => write!(
                f,
                "ERROR TR-31: Invalid MAC length: expected {} bytes, found {}",
                expected, actual
            ),

            Self::MacVerificationFailed => write!(f, "ERROR TR-31: MAC check failed"),

            Self::Header(error) => Display::fmt(error, f),

            Self::Payload(error) => Display::fmt(error, f),

            Self::Hex(error) => Display::fmt(error, f),

            Self::KeyBlockLengthTooLarge { maximum, actual } => write!(
                f,
                "ERROR TR-31: Key block length exceeds maximum: maximum {}, actual {}",
                maximum, actual
            ),
        }
    }
}

impl Error for Tr31Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Header(error) => Some(error),
            Self::Payload(error) => Some(error),
            Self::Hex(error) => Some(error),

            _ => None,
        }
    }
}

impl From<KeyBlockHeaderError> for Tr31Error {
    fn from(error: KeyBlockHeaderError) -> Self {
        Self::Header(error)
    }
}

impl From<PayloadError> for Tr31Error {
    fn from(error: PayloadError) -> Self {
        Self::Payload(error)
    }
}

impl From<hex::FromHexError> for Tr31Error {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}

/// Error returned by TR-31 operations that may invoke a cryptographic
/// provider.
#[derive(Debug)]
pub enum Tr31CryptoError<E> {
    /// TR-31 parsing, validation, or formatting failed.
    Tr31(Tr31Error),

    /// The cryptographic provider reported an error.
    Crypto(E),
}

impl<E> Display for Tr31CryptoError<E>
where
    E: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tr31(error) => Display::fmt(error, f),

            Self::Crypto(error) => Display::fmt(error, f),
        }
    }
}

impl<E> Error for Tr31CryptoError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tr31(error) => Some(error),
            Self::Crypto(error) => Some(error),
        }
    }
}

impl<E> From<Tr31Error> for Tr31CryptoError<E> {
    fn from(error: Tr31Error) -> Self {
        Self::Tr31(error)
    }
}

impl<E> From<KeyBlockHeaderError> for Tr31CryptoError<E> {
    fn from(error: KeyBlockHeaderError) -> Self {
        Self::Tr31(Tr31Error::Header(error))
    }
}

impl<E> From<PayloadError> for Tr31CryptoError<E> {
    fn from(error: PayloadError) -> Self {
        Self::Tr31(Tr31Error::Payload(error))
    }
}

impl<E> From<hex::FromHexError> for Tr31CryptoError<E> {
    fn from(error: hex::FromHexError) -> Self {
        Self::Tr31(Tr31Error::Hex(error))
    }
}
