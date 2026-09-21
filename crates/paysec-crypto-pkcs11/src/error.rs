use std::error::Error;
use std::fmt::{Display, Formatter};

/// Error returned by the PKCS #11 cryptographic provider.
///
/// Errors originating from the PKCS #11 implementation retain the
/// corresponding `cryptoki` error as their source. Provider-level errors,
/// such as invalid input or ambiguous object selection, contain only a
/// descriptive message.
#[derive(Debug)]
pub struct Pkcs11Error {
    message: String,
    source: Option<cryptoki::error::Error>,
}

impl Pkcs11Error {
    /// Creates an error originating in the provider itself.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Creates an error caused by an underlying PKCS #11 operation.
    pub(crate) fn cryptoki(message: impl Into<String>, source: cryptoki::error::Error) -> Self {
        Self {
            message: message.into(),
            source: Some(source),
        }
    }

    /// Creates an error for an unsupported AES key length.
    pub(crate) fn invalid_aes_key_length(length: usize) -> Self {
        Self::new(format!("unsupported AES key length: {length} bytes"))
    }
}

impl Display for Pkcs11Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;

        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }

        Ok(())
    }
}

impl Error for Pkcs11Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}
