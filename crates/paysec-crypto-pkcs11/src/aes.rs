use cryptoki::mechanism::Mechanism;
use cryptoki::object::{KeyType, ObjectClass};
use paysec_crypto::AesBlockCipher;

use crate::object::resolve_key;
use crate::{Pkcs11Error, Pkcs11Key, Pkcs11Provider};

impl AesBlockCipher<Pkcs11Key> for Pkcs11Provider {
    fn encrypt_block(&self, key: &Pkcs11Key, block: &[u8; 16]) -> Result<[u8; 16], Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            let output = session
                .encrypt(&Mechanism::AesEcb, key, block)
                .map_err(|error| Pkcs11Error::cryptoki("failed to encrypt AES block", error))?;

            aes_block_from_output(output, "encryption")
        })
    }

    fn decrypt_block(&self, key: &Pkcs11Key, block: &[u8; 16]) -> Result<[u8; 16], Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            let output = session
                .decrypt(&Mechanism::AesEcb, key, block)
                .map_err(|error| Pkcs11Error::cryptoki("failed to decrypt AES block", error))?;

            aes_block_from_output(output, "decryption")
        })
    }
}

fn aes_block_from_output(
    output: Vec<u8>,
    operation: &'static str,
) -> Result<[u8; 16], Pkcs11Error> {
    let output_len = output.len();

    output.as_slice().try_into().map_err(|_| {
        Pkcs11Error::new(format!(
            "PKCS #11 AES block {operation} returned {output_len} bytes; expected 16"
        ))
    })
}
