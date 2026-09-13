use std::error::Error;
use std::fmt::{Display, Formatter};

use paysec_crypto::{AesBlockCipher, AesCbc, AesCmac, CryptoProvider};
use soft_aes::aes::{aes_cmac, aes_dec_block, aes_dec_cbc, aes_enc_block, aes_enc_cbc};

#[derive(Debug, Default, Clone, Copy)]
pub struct SoftAesProvider;

impl SoftAesProvider {
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug)]
pub struct SoftAesError {
    message: String,
}

impl Display for SoftAesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for SoftAesError {}

impl From<Box<dyn Error>> for SoftAesError {
    fn from(error: Box<dyn Error>) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

impl CryptoProvider for SoftAesProvider {
    type Error = SoftAesError;
}

impl AesBlockCipher<[u8]> for SoftAesProvider {
    fn encrypt_block(&self, key: &[u8], block: &[u8; 16]) -> Result<[u8; 16], Self::Error> {
        aes_enc_block(block, key).map_err(SoftAesError::from)
    }

    fn decrypt_block(&self, key: &[u8], block: &[u8; 16]) -> Result<[u8; 16], Self::Error> {
        aes_dec_block(block, key).map_err(SoftAesError::from)
    }
}

impl AesCbc<[u8]> for SoftAesProvider {
    fn encrypt_cbc(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        aes_enc_cbc(plaintext, key, iv, None).map_err(SoftAesError::from)
    }

    fn decrypt_cbc(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        aes_dec_cbc(ciphertext, key, iv, None).map_err(SoftAesError::from)
    }
}

impl AesCmac<[u8]> for SoftAesProvider {
    fn calculate_cmac(&self, key: &[u8], message: &[u8]) -> Result<[u8; 16], Self::Error> {
        aes_cmac(message, key).map_err(SoftAesError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_128_block_cipher_matches_known_vector() {
        let provider = SoftAesProvider::new();

        let key = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();

        let plaintext: [u8; 16] = hex::decode("00112233445566778899AABBCCDDEEFF")
            .unwrap()
            .try_into()
            .unwrap();

        let expected: [u8; 16] = hex::decode("69C4E0D86A7B0430D8CDB78070B4C55A")
            .unwrap()
            .try_into()
            .unwrap();

        let encrypted = provider.encrypt_block(&key, &plaintext).unwrap();

        assert_eq!(encrypted, expected);

        let decrypted = provider.decrypt_block(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_128_cmac_matches_known_vector() {
        let provider = SoftAesProvider::new();

        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();

        let message = hex::decode("6BC1BEE22E409F96E93D7E117393172A").unwrap();

        let expected: [u8; 16] = hex::decode("070A16B46B4D4144F79BDD9DD04A287C")
            .unwrap()
            .try_into()
            .unwrap();

        let mac = provider.calculate_cmac(&key, &message).unwrap();

        assert_eq!(mac, expected);
    }
}
