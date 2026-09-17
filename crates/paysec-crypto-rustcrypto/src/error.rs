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

    pub(crate) fn random_generation_failed() -> Self {
        Self::new("random byte generation failed")
    }

    pub(crate) fn rsa_oaep_encryption_failed() -> Self {
        Self::new("RSA-OAEP encryption failed")
    }

    pub(crate) fn rsa_signing_failed() -> Self {
        Self::new("RSA PKCS#1 v1.5 signing failed")
    }

    pub(crate) fn rsa_verification_failed() -> Self {
        Self::new("RSA PKCS#1 v1.5 signature verification failed")
    }
}

impl Display for RustCryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for RustCryptoError {}
