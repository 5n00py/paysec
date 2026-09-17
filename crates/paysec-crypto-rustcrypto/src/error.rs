use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustCryptoError {
    message: String,
}

impl RustCryptoError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(crate) fn invalid_key_length(length: usize) -> Self {
        Self::new(format!("unsupported AES key length: {length} bytes"))
    }
}

impl Display for RustCryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for RustCryptoError {}
