use crate::CryptoProvider;

/// Cryptographically secure random-byte generation.
///
/// Production implementations must return cryptographically secure,
/// unpredictable random bytes.
///
/// Deterministic implementations may be used for test vectors and
/// conformance testing.
pub trait RandomBytes: CryptoProvider {
    fn fill_random(&mut self, output: &mut [u8]) -> Result<(), Self::Error>;
}
