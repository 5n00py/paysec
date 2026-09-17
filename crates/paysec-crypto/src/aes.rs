use crate::CryptoProvider;

/// AES single-block encryption and decryption.
///
/// The key type is intentionally generic so providers can operate on
/// clear key material, opaque key handles, or other key representations.
pub trait AesBlockCipher<K: ?Sized>: CryptoProvider {
    fn encrypt_block(&self, key: &K, block: &[u8; 16]) -> Result<[u8; 16], Self::Error>;

    fn decrypt_block(&self, key: &K, block: &[u8; 16]) -> Result<[u8; 16], Self::Error>;
}

/// AES-CBC encryption and decryption without padding.
///
/// Input data must be aligned to the AES block size.
pub trait AesCbc<K: ?Sized>: CryptoProvider {
    fn encrypt_cbc(&self, key: &K, iv: &[u8; 16], plaintext: &[u8])
    -> Result<Vec<u8>, Self::Error>;

    fn decrypt_cbc(
        &self,
        key: &K,
        iv: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// AES-CMAC calculation.
pub trait AesCmac<K: ?Sized>: CryptoProvider {
    fn calculate_cmac(&self, key: &K, message: &[u8]) -> Result<[u8; 16], Self::Error>;
}

/// Supported AES key sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeySize {
    Bits128,
    Bits192,
    Bits256,
}

impl AesKeySize {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bits128 => 16,
            Self::Bits192 => 24,
            Self::Bits256 => 32,
        }
    }
}

impl TryFrom<usize> for AesKeySize {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            16 => Ok(Self::Bits128),
            24 => Ok(Self::Bits192),
            32 => Ok(Self::Bits256),
            _ => Err("unsupported AES key length"),
        }
    }
}

/// Derive a key using one or more AES-CMAC derivation inputs.
///
/// The derived key type is provider-specific. Software providers may return
/// raw key material, while an HSM provider may return an opaque key handle.
pub trait AesCmacKeyDerivation<K: ?Sized>: CryptoProvider {
    type DerivedKey;

    fn derive_key_cmac(
        &self,
        key: &K,
        derivation_inputs: &[&[u8]],
        output_len: usize,
    ) -> Result<Self::DerivedKey, Self::Error>;
}
