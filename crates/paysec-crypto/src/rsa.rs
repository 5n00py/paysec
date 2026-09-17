use crate::CryptoProvider;

/// RSAES-OAEP encryption using the TR-34 algorithm profile:
///
/// - SHA-256
/// - MGF1 with SHA-256
/// - empty label
///
/// OAEP randomness is owned by the provider. Software providers may use
/// injected entropy to support deterministic test vectors, while an HSM
/// provider may generate the OAEP seed internally.
pub trait RsaOaepSha256Encrypt<K: ?Sized>: CryptoProvider {
    fn encrypt_oaep_sha256(&mut self, key: &K, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// RSASSA-PKCS1-v1_5 signature generation using SHA-256.
///
/// `message` is the message to hash and sign, not a precomputed digest.
pub trait RsaPkcs1v15Sha256Sign<K: ?Sized>: CryptoProvider {
    fn sign_pkcs1v15_sha256(&self, key: &K, message: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// RSASSA-PKCS1-v1_5 signature verification using SHA-256.
///
/// `message` is the original message, not a precomputed digest.
pub trait RsaPkcs1v15Sha256Verify<K: ?Sized>: CryptoProvider {
    fn verify_pkcs1v15_sha256(
        &self,
        key: &K,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error>;
}
