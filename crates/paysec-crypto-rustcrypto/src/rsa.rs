use paysec_crypto::{RsaOaepSha256Encrypt, RsaPkcs1v15Sha256Sign, RsaPkcs1v15Sha256Verify};

use rand_core::{CryptoRng, OsRng, RngCore};

use ::rsa::{Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use sha2::{Digest, Sha256};

use crate::{RustCryptoError, RustCryptoProvider, RustCryptoProviderWithRng};

fn encrypt_oaep_sha256_with_rng<R>(
    rng: &mut R,
    key: &RsaPublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, RustCryptoError>
where
    R: RngCore + CryptoRng,
{
    key.encrypt(rng, Oaep::new::<Sha256>(), plaintext)
        .map_err(|_| RustCryptoError::rsa_oaep_encryption_failed())
}

fn sign_pkcs1v15_sha256(key: &RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>, RustCryptoError> {
    let digest = Sha256::digest(message);
    let padding = Pkcs1v15Sign::new::<Sha256>();

    // PKCS#1 v1.5 signatures are deterministic. The RNG is used only for
    // RSA blinding of the private-key operation.
    let mut rng = OsRng;

    key.sign_with_rng(&mut rng, padding, digest.as_slice())
        .map_err(|_| RustCryptoError::rsa_signing_failed())
}

fn verify_pkcs1v15_sha256(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), RustCryptoError> {
    let digest = Sha256::digest(message);
    let padding = Pkcs1v15Sign::new::<Sha256>();

    key.verify(padding, digest.as_slice(), signature)
        .map_err(|_| RustCryptoError::rsa_verification_failed())
}

impl RsaOaepSha256Encrypt<RsaPublicKey> for RustCryptoProvider {
    fn encrypt_oaep_sha256(
        &mut self,
        key: &RsaPublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let mut rng = OsRng;

        encrypt_oaep_sha256_with_rng(&mut rng, key, plaintext)
    }
}

impl<R> RsaOaepSha256Encrypt<RsaPublicKey> for RustCryptoProviderWithRng<R>
where
    R: RngCore + CryptoRng,
{
    fn encrypt_oaep_sha256(
        &mut self,
        key: &RsaPublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        encrypt_oaep_sha256_with_rng(self.rng_mut(), key, plaintext)
    }
}

impl RsaPkcs1v15Sha256Sign<RsaPrivateKey> for RustCryptoProvider {
    fn sign_pkcs1v15_sha256(
        &self,
        key: &RsaPrivateKey,
        message: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        sign_pkcs1v15_sha256(key, message)
    }
}

impl<R> RsaPkcs1v15Sha256Sign<RsaPrivateKey> for RustCryptoProviderWithRng<R> {
    fn sign_pkcs1v15_sha256(
        &self,
        key: &RsaPrivateKey,
        message: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        sign_pkcs1v15_sha256(key, message)
    }
}

impl RsaPkcs1v15Sha256Verify<RsaPublicKey> for RustCryptoProvider {
    fn verify_pkcs1v15_sha256(
        &self,
        key: &RsaPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        verify_pkcs1v15_sha256(key, message, signature)
    }
}

impl<R> RsaPkcs1v15Sha256Verify<RsaPublicKey> for RustCryptoProviderWithRng<R> {
    fn verify_pkcs1v15_sha256(
        &self,
        key: &RsaPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        verify_pkcs1v15_sha256(key, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl FixedRng {
        fn new(bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                bytes: bytes.into(),
                offset: 0,
            }
        }

        fn consumed(&self) -> usize {
            self.offset
        }
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.offset + dest.len();

            assert!(end <= self.bytes.len(), "fixed RNG exhausted");

            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}

    fn rsa_key_pair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = OsRng;

        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        let public_key = RsaPublicKey::from(&private_key);

        (private_key, public_key)
    }

    #[test]
    fn oaep_sha256_round_trip() {
        let (private_key, public_key) = rsa_key_pair();

        let mut provider = RustCryptoProvider::new();

        let plaintext = b"0123456789ABCDEF";

        let ciphertext = provider
            .encrypt_oaep_sha256(&public_key, plaintext)
            .unwrap();

        let decrypted = private_key
            .decrypt(Oaep::new::<Sha256>(), &ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn oaep_sha256_is_deterministic_with_fixed_seed() {
        let (_private_key, public_key) = rsa_key_pair();

        // OAEP with SHA-256 uses a 32-byte seed.
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let mut provider_a = RustCryptoProvider::with_rng(FixedRng::new(seed));

        let mut provider_b = RustCryptoProvider::with_rng(FixedRng::new(seed));

        let plaintext = b"0123456789ABCDEF";

        let ciphertext_a = provider_a
            .encrypt_oaep_sha256(&public_key, plaintext)
            .unwrap();

        let ciphertext_b = provider_b
            .encrypt_oaep_sha256(&public_key, plaintext)
            .unwrap();

        assert_eq!(ciphertext_a, ciphertext_b);

        // This also proves RustCrypto consumed exactly the SHA-256-sized
        // OAEP seed and no additional protocol-visible randomness.
        assert_eq!(provider_a.into_rng().consumed(), 32);
        assert_eq!(provider_b.into_rng().consumed(), 32);
    }

    #[test]
    fn different_oaep_seeds_produce_different_ciphertexts() {
        let (_private_key, public_key) = rsa_key_pair();

        let mut provider_a = RustCryptoProvider::with_rng(FixedRng::new([0x11; 32]));

        let mut provider_b = RustCryptoProvider::with_rng(FixedRng::new([0x22; 32]));

        let plaintext = b"0123456789ABCDEF";

        let ciphertext_a = provider_a
            .encrypt_oaep_sha256(&public_key, plaintext)
            .unwrap();

        let ciphertext_b = provider_b
            .encrypt_oaep_sha256(&public_key, plaintext)
            .unwrap();

        assert_ne!(ciphertext_a, ciphertext_b);
    }

    #[test]
    fn pkcs1v15_sha256_sign_and_verify() {
        let (private_key, public_key) = rsa_key_pair();

        let provider = RustCryptoProvider::new();

        let message = b"TR-34 test message";

        let signature = provider
            .sign_pkcs1v15_sha256(&private_key, message)
            .unwrap();

        provider
            .verify_pkcs1v15_sha256(&public_key, message, &signature)
            .unwrap();
    }

    #[test]
    fn pkcs1v15_sha256_signature_is_deterministic() {
        let (private_key, _public_key) = rsa_key_pair();

        let provider = RustCryptoProvider::new();

        let message = b"TR-34 test message";

        let signature_a = provider
            .sign_pkcs1v15_sha256(&private_key, message)
            .unwrap();

        let signature_b = provider
            .sign_pkcs1v15_sha256(&private_key, message)
            .unwrap();

        assert_eq!(signature_a, signature_b);
    }

    #[test]
    fn pkcs1v15_sha256_rejects_modified_message() {
        let (private_key, public_key) = rsa_key_pair();

        let provider = RustCryptoProvider::new();

        let signature = provider
            .sign_pkcs1v15_sha256(&private_key, b"original")
            .unwrap();

        let result = provider.verify_pkcs1v15_sha256(&public_key, b"modified", &signature);

        assert!(result.is_err());
    }

    #[test]
    fn pkcs1v15_sha256_rejects_modified_signature() {
        let (private_key, public_key) = rsa_key_pair();

        let provider = RustCryptoProvider::new();

        let message = b"TR-34 test message";

        let mut signature = provider
            .sign_pkcs1v15_sha256(&private_key, message)
            .unwrap();

        signature[0] ^= 0x01;

        let result = provider.verify_pkcs1v15_sha256(&public_key, message, &signature);

        assert!(result.is_err());
    }

    #[test]
    fn oaep_sha256_rejects_oversized_plaintext() {
        let (_private_key, public_key) = rsa_key_pair();

        let mut provider = RustCryptoProvider::new();

        // RSA-2048 + SHA-256 OAEP supports at most:
        //
        // 256 - 2 * 32 - 2 = 190 bytes.
        let plaintext = vec![0u8; 191];

        let result = provider.encrypt_oaep_sha256(&public_key, &plaintext);

        assert!(result.is_err());
    }
}
