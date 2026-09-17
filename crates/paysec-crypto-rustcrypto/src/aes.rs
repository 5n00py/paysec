use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt};
use aes::{Aes128, Aes192, Aes256};

use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, block_padding::NoPadding};

use cmac::{Cmac, Mac};

use paysec_crypto::{AesBlockCipher, AesCbc, AesCmac, AesCmacKeyDerivation};

use crate::{RustCryptoError, RustCryptoProvider};

const AES_BLOCK_SIZE: usize = 16;

impl AesBlockCipher<[u8]> for RustCryptoProvider {
    fn encrypt_block(
        &self,
        key: &[u8],
        block: &[u8; AES_BLOCK_SIZE],
    ) -> Result<[u8; AES_BLOCK_SIZE], Self::Error> {
        let mut output = Array::from(*block);

        match key.len() {
            16 => {
                let cipher = <Aes128 as aes::cipher::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher.encrypt_block(&mut output);
            }

            24 => {
                let cipher = <Aes192 as aes::cipher::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher.encrypt_block(&mut output);
            }

            32 => {
                let cipher = <Aes256 as aes::cipher::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher.encrypt_block(&mut output);
            }

            length => {
                return Err(RustCryptoError::invalid_key_length(length));
            }
        }

        let mut result = [0u8; AES_BLOCK_SIZE];
        result.copy_from_slice(&output);

        Ok(result)
    }

    fn decrypt_block(
        &self,
        key: &[u8],
        block: &[u8; AES_BLOCK_SIZE],
    ) -> Result<[u8; AES_BLOCK_SIZE], Self::Error> {
        let mut output = Array::from(*block);

        match key.len() {
            16 => {
                let cipher = <Aes128 as aes::cipher::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher.decrypt_block(&mut output);
            }

            24 => {
                let cipher = <Aes192 as aes::cipher::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher.decrypt_block(&mut output);
            }

            32 => {
                let cipher = <Aes256 as aes::cipher::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher.decrypt_block(&mut output);
            }

            length => {
                return Err(RustCryptoError::invalid_key_length(length));
            }
        }

        let mut result = [0u8; AES_BLOCK_SIZE];
        result.copy_from_slice(&output);

        Ok(result)
    }
}

impl AesCbc<[u8]> for RustCryptoProvider {
    fn encrypt_cbc(
        &self,
        key: &[u8],
        iv: &[u8; AES_BLOCK_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err(RustCryptoError::new(
                "AES-CBC plaintext length must be a multiple of 16 bytes",
            ));
        }

        match key.len() {
            16 => {
                let cipher =
                    <cbc::Encryptor<Aes128> as cbc::cipher::KeyIvInit>::new_from_slices(key, iv)
                        .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                Ok(cipher.encrypt_padded_vec::<NoPadding>(plaintext))
            }

            24 => {
                let cipher =
                    <cbc::Encryptor<Aes192> as cbc::cipher::KeyIvInit>::new_from_slices(key, iv)
                        .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                Ok(cipher.encrypt_padded_vec::<NoPadding>(plaintext))
            }

            32 => {
                let cipher =
                    <cbc::Encryptor<Aes256> as cbc::cipher::KeyIvInit>::new_from_slices(key, iv)
                        .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                Ok(cipher.encrypt_padded_vec::<NoPadding>(plaintext))
            }

            length => Err(RustCryptoError::invalid_key_length(length)),
        }
    }

    fn decrypt_cbc(
        &self,
        key: &[u8],
        iv: &[u8; AES_BLOCK_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(RustCryptoError::new(
                "AES-CBC ciphertext length must be a multiple of 16 bytes",
            ));
        }

        match key.len() {
            16 => {
                let cipher =
                    <cbc::Decryptor<Aes128> as cbc::cipher::KeyIvInit>::new_from_slices(key, iv)
                        .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher
                    .decrypt_padded_vec::<NoPadding>(ciphertext)
                    .map_err(|_| RustCryptoError::new("AES-CBC decryption failed"))
            }

            24 => {
                let cipher =
                    <cbc::Decryptor<Aes192> as cbc::cipher::KeyIvInit>::new_from_slices(key, iv)
                        .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher
                    .decrypt_padded_vec::<NoPadding>(ciphertext)
                    .map_err(|_| RustCryptoError::new("AES-CBC decryption failed"))
            }

            32 => {
                let cipher =
                    <cbc::Decryptor<Aes256> as cbc::cipher::KeyIvInit>::new_from_slices(key, iv)
                        .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                cipher
                    .decrypt_padded_vec::<NoPadding>(ciphertext)
                    .map_err(|_| RustCryptoError::new("AES-CBC decryption failed"))
            }

            length => Err(RustCryptoError::invalid_key_length(length)),
        }
    }
}

impl AesCmac<[u8]> for RustCryptoProvider {
    fn calculate_cmac(
        &self,
        key: &[u8],
        message: &[u8],
    ) -> Result<[u8; AES_BLOCK_SIZE], Self::Error> {
        let bytes = match key.len() {
            16 => {
                let mut mac = <Cmac<Aes128> as cmac::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                mac.update(message);
                mac.finalize().into_bytes()
            }

            24 => {
                let mut mac = <Cmac<Aes192> as cmac::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                mac.update(message);
                mac.finalize().into_bytes()
            }

            32 => {
                let mut mac = <Cmac<Aes256> as cmac::KeyInit>::new_from_slice(key)
                    .map_err(|_| RustCryptoError::invalid_key_length(key.len()))?;

                mac.update(message);
                mac.finalize().into_bytes()
            }

            length => {
                return Err(RustCryptoError::invalid_key_length(length));
            }
        };

        let mut result = [0u8; AES_BLOCK_SIZE];
        result.copy_from_slice(&bytes);

        Ok(result)
    }
}

impl AesCmacKeyDerivation<[u8]> for RustCryptoProvider {
    type DerivedKey = Vec<u8>;

    fn derive_key_cmac(
        &self,
        key: &[u8],
        derivation_inputs: &[&[u8]],
        output_len: usize,
    ) -> Result<Self::DerivedKey, Self::Error> {
        let available_len = derivation_inputs.len() * AES_BLOCK_SIZE;

        if output_len > available_len {
            return Err(RustCryptoError::new(
                "insufficient CMAC output for requested derived key length",
            ));
        }

        let mut derived_key = Vec::with_capacity(available_len);

        for input in derivation_inputs {
            let block = <Self as AesCmac<[u8]>>::calculate_cmac(self, key, input)?;

            derived_key.extend_from_slice(&block);
        }

        derived_key.truncate(output_len);

        Ok(derived_key)
    }
}

// Derived software keys are represented as Vec<u8>.
//
// These implementations allow TR-31 to pass provider-derived KBEK and KBAK
// directly back to the provider without exposing any assumptions about their
// representation in the paysec-keyblock crate.

impl AesCbc<Vec<u8>> for RustCryptoProvider {
    fn encrypt_cbc(
        &self,
        key: &Vec<u8>,
        iv: &[u8; AES_BLOCK_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        <Self as AesCbc<[u8]>>::encrypt_cbc(self, key.as_slice(), iv, plaintext)
    }

    fn decrypt_cbc(
        &self,
        key: &Vec<u8>,
        iv: &[u8; AES_BLOCK_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        <Self as AesCbc<[u8]>>::decrypt_cbc(self, key.as_slice(), iv, ciphertext)
    }
}

impl AesCmac<Vec<u8>> for RustCryptoProvider {
    fn calculate_cmac(
        &self,
        key: &Vec<u8>,
        message: &[u8],
    ) -> Result<[u8; AES_BLOCK_SIZE], Self::Error> {
        <Self as AesCmac<[u8]>>::calculate_cmac(self, key.as_slice(), message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_128_block_cipher_matches_known_vector() {
        let provider = RustCryptoProvider::new();

        let key = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();

        let plaintext: [u8; 16] = hex::decode("00112233445566778899AABBCCDDEEFF")
            .unwrap()
            .try_into()
            .unwrap();

        let expected: [u8; 16] = hex::decode("69C4E0D86A7B0430D8CDB78070B4C55A")
            .unwrap()
            .try_into()
            .unwrap();

        let encrypted = provider.encrypt_block(key.as_slice(), &plaintext).unwrap();

        assert_eq!(encrypted, expected);

        let decrypted = provider.decrypt_block(key.as_slice(), &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_128_cmac_matches_known_vector() {
        let provider = RustCryptoProvider::new();

        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();

        let message = hex::decode("6BC1BEE22E409F96E93D7E117393172A").unwrap();

        let expected: [u8; 16] = hex::decode("070A16B46B4D4144F79BDD9DD04A287C")
            .unwrap()
            .try_into()
            .unwrap();

        let result = provider.calculate_cmac(key.as_slice(), &message).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_cbc_round_trip_without_padding() {
        let provider = RustCryptoProvider::new();

        let key = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

        let iv = [0u8; 16];

        let plaintext = hex::decode(
            "00112233445566778899AABBCCDDEEFF\
             FFEEDDCCBBAA99887766554433221100",
        )
        .unwrap();

        let ciphertext = provider
            .encrypt_cbc(key.as_slice(), &iv, &plaintext)
            .unwrap();

        let decrypted = provider
            .decrypt_cbc(key.as_slice(), &iv, &ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
