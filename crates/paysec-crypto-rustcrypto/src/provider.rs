use paysec_crypto::CryptoProvider;

use crate::RustCryptoError;

#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoProvider;

impl RustCryptoProvider {
    pub const fn new() -> Self {
        Self
    }

    pub const fn with_rng<R>(rng: R) -> RustCryptoProviderWithRng<R> {
        RustCryptoProviderWithRng::new(rng)
    }
}

impl CryptoProvider for RustCryptoProvider {
    type Error = RustCryptoError;
}

/// RustCrypto provider using a caller-supplied cryptographically secure
/// random number generator.
///
/// This variant is useful when randomness must be controlled externally,
/// including deterministic conformance and test-vector generation.
#[derive(Debug)]
pub struct RustCryptoProviderWithRng<R> {
    rng: R,
}

impl<R> RustCryptoProviderWithRng<R> {
    pub const fn new(rng: R) -> Self {
        Self { rng }
    }

    pub fn rng_mut(&mut self) -> &mut R {
        &mut self.rng
    }

    pub fn into_rng(self) -> R {
        self.rng
    }
}

impl<R> CryptoProvider for RustCryptoProviderWithRng<R> {
    type Error = RustCryptoError;
}
