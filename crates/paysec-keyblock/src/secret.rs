use std::fmt::{Debug, Formatter};

use zeroize::Zeroizing;

/// Plaintext cryptographic key material owned by `paysec-keyblock`.
///
/// `SecretKey` provides basic in-process protection for plaintext key
/// material:
///
/// - its contents are redacted from [`Debug`] output,
/// - its owned byte buffer is zeroized when dropped,
/// - raw key bytes are available only through an explicit
///   [`SecretKey::expose_secret`] call.
///
/// This type is intended for plaintext key material handled by the TR-31
/// domain layer. It is not used for provider-managed keys such as KBPK,
/// KBEK, or KBAK, which may be represented by opaque HSM handles or other
/// provider-specific types.
///
/// # Security
///
/// `SecretKey` provides memory-hygiene and accidental-disclosure protection.
/// It does not guarantee that key material has never existed elsewhere in
/// process memory. For example, callers may retain their own copies, and
/// operating-system facilities such as swap, crash dumps, or process memory
/// inspection are outside the scope of this type.
pub struct SecretKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretKey {
    /// Create a secret key by taking ownership of an existing byte vector.
    ///
    /// Taking ownership avoids making an additional copy of the key material.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Create a secret key by copying key material from a byte slice.
    ///
    /// The caller remains responsible for any original copy represented by
    /// `bytes`.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// Explicitly expose the plaintext key bytes.
    ///
    /// This operation is intentionally named to make access to plaintext key
    /// material visible during code review.
    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Return the key length in bytes without exposing the key material.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the key contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl From<Vec<u8>> for SecretKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}
