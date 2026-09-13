use std::error::Error;

/// Base trait implemented by cryptographic providers.
pub trait CryptoProvider {
    type Error: Error + 'static;
}

/// AES single-block encryption and decryption.
///
/// The key type is intentionally generic so providers can operate on
/// clear key material, opaque key handles, or other key representations.
pub trait AesBlockCipher<K: ?Sized>: CryptoProvider {
    fn encrypt_block(
        &self,
        key: &K,
        block: &[u8; 16],
    ) -> Result<[u8; 16], Self::Error>;

    fn decrypt_block(
        &self,
        key: &K,
        block: &[u8; 16],
    ) -> Result<[u8; 16], Self::Error>;
}

/// AES-CBC encryption and decryption without padding.
///
/// Input data must be aligned to the AES block size.
pub trait AesCbc<K: ?Sized>: CryptoProvider {
    fn encrypt_cbc(
        &self,
        key: &K,
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn decrypt_cbc(
        &self,
        key: &K,
        iv: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// AES-CMAC calculation.
pub trait AesCmac<K: ?Sized>: CryptoProvider {
    fn calculate_cmac(
        &self,
        key: &K,
        message: &[u8],
    ) -> Result<[u8; 16], Self::Error>;
}
