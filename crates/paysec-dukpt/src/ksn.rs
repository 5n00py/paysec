use crate::InitialKeyId;

/// Native ANSI X9.24-3 AES DUKPT Key Serial Number.
///
/// A native AES DUKPT KSN is 96 bits:
///
/// ```text
/// bytes 0-7    Initial Key ID
/// bytes 8-11   Transaction Counter
/// ```
///
/// The KSN is non-secret information transmitted with a transaction so that
/// the receiving system can reconstruct the corresponding DUKPT working key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeySerialNumber {
    initial_key_id: InitialKeyId,
    transaction_counter: u32,
}

impl KeySerialNumber {
    /// Creates a native AES DUKPT KSN.
    pub const fn new(initial_key_id: InitialKeyId, transaction_counter: u32) -> Self {
        Self {
            initial_key_id,
            transaction_counter,
        }
    }

    /// Creates a KSN directly from its component identifiers.
    pub fn from_parts(bdk_id: u32, derivation_id: u32, transaction_counter: u32) -> Self {
        Self::new(
            InitialKeyId::from_parts(bdk_id, derivation_id),
            transaction_counter,
        )
    }

    /// Creates a KSN from its encoded 12-byte representation.
    pub fn from_bytes(value: [u8; 12]) -> Self {
        let initial_key_id = InitialKeyId::new(
            value[..8]
                .try_into()
                .expect("slice length is fixed at eight bytes"),
        );

        let transaction_counter = u32::from_be_bytes(
            value[8..12]
                .try_into()
                .expect("slice length is fixed at four bytes"),
        );

        Self::new(initial_key_id, transaction_counter)
    }

    /// Returns the Initial Key ID.
    pub const fn initial_key_id(&self) -> InitialKeyId {
        self.initial_key_id
    }

    /// Returns the transaction counter.
    pub const fn transaction_counter(&self) -> u32 {
        self.transaction_counter
    }

    /// Returns the encoded 12-byte KSN.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut value = [0u8; 12];

        value[..8].copy_from_slice(self.initial_key_id.as_bytes());

        value[8..].copy_from_slice(&self.transaction_counter.to_be_bytes());

        value
    }
}

impl From<[u8; 12]> for KeySerialNumber {
    fn from(value: [u8; 12]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<KeySerialNumber> for [u8; 12] {
    fn from(value: KeySerialNumber) -> Self {
        value.to_bytes()
    }
}
