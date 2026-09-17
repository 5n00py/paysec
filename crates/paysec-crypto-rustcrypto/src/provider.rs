use paysec_crypto::CryptoProvider;

use crate::RustCryptoError;

#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoProvider;

impl RustCryptoProvider {
    pub const fn new() -> Self {
        Self
    }
}

impl CryptoProvider for RustCryptoProvider {
    type Error = RustCryptoError;
}
