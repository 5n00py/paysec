/// ANSI X9.24-3 AES DUKPT Initial Key Identifier.
///
/// The Initial Key ID is a 64-bit non-secret identifier consisting of:
///
/// - a 32-bit Base Derivation Key ID, and
/// - a 32-bit Derivation ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InitialKeyId([u8; 8]);

impl InitialKeyId {
    /// Creates an Initial Key ID from its encoded 8-byte representation.
    pub const fn new(value: [u8; 8]) -> Self {
        Self(value)
    }

    /// Creates an Initial Key ID from its BDK ID and Derivation ID.
    pub fn from_parts(bdk_id: u32, derivation_id: u32) -> Self {
        let mut value = [0u8; 8];

        value[..4].copy_from_slice(&bdk_id.to_be_bytes());

        value[4..].copy_from_slice(&derivation_id.to_be_bytes());

        Self(value)
    }

    /// Returns the encoded Initial Key ID.
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl From<[u8; 8]> for InitialKeyId {
    fn from(value: [u8; 8]) -> Self {
        Self::new(value)
    }
}
