use std::error::Error;

/// Base trait implemented by cryptographic providers.
pub trait CryptoProvider {
    type Error: Error + 'static;
}
