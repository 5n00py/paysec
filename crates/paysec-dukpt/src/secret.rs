use std::fmt;

use zeroize::Zeroizing;

/// Secret AES DUKPT key material.
///
/// The owned key bytes are zeroized when this value is dropped.
///
/// Debug output is redacted. Raw key access requires an explicit call to
/// [`DukptKey::expose_secret`].
pub struct DukptKey {
    value: Zeroizing<Vec<u8>>,
}

impl DukptKey {
    /// Creates a DUKPT key from owned plaintext key material.
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value: Zeroizing::new(value),
        }
    }

    /// Creates a DUKPT key by copying plaintext key material.
    pub fn from_slice(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }

    /// Explicitly exposes the plaintext key bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Returns the key length in bytes.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns whether the contained key is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub(crate) fn from_zeroizing(value: Zeroizing<Vec<u8>>) -> Self {
        Self { value }
    }
}

impl fmt::Debug for DukptKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DukptKey([REDACTED])")
    }
}
