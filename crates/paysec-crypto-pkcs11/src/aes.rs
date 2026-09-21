use cryptoki::mechanism::Mechanism;
use cryptoki::object::{KeyType, ObjectClass};
use paysec_crypto::{AesBlockCipher, AesCbc, AesCmac};

use crate::object::resolve_key;
use crate::{Pkcs11Error, Pkcs11Key, Pkcs11Provider};

const AES_BLOCK_SIZE: usize = 16;
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

impl AesCbc<Pkcs11Key> for Pkcs11Provider {
    fn encrypt_cbc(
        &self,
        key: &Pkcs11Key,
        iv: &[u8; AES_BLOCK_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err(Pkcs11Error::new(
                "AES-CBC plaintext length must be a multiple of 16 bytes",
            ));
        }

        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            session
                .encrypt(&Mechanism::AesCbc(*iv), key, plaintext)
                .map_err(|error| Pkcs11Error::cryptoki("failed to encrypt AES-CBC data", error))
        })
    }

    fn decrypt_cbc(
        &self,
        key: &Pkcs11Key,
        iv: &[u8; AES_BLOCK_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(Pkcs11Error::new(
                "AES-CBC ciphertext length must be a multiple of 16 bytes",
            ));
        }

        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            session
                .decrypt(&Mechanism::AesCbc(*iv), key, ciphertext)
                .map_err(|error| Pkcs11Error::cryptoki("failed to decrypt AES-CBC data", error))
        })
    }
}

impl AesCmac<Pkcs11Key> for Pkcs11Provider {
    fn calculate_cmac(&self, key: &Pkcs11Key, message: &[u8]) -> Result<[u8; 16], Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            let mac = session
                .sign(&Mechanism::AesCMac, key, message)
                .map_err(|error| Pkcs11Error::cryptoki("failed to calculate AES-CMAC", error))?;

            let mac_len = mac.len();

            mac.as_slice().try_into().map_err(|_| {
                Pkcs11Error::new(format!(
                    "PKCS #11 AES-CMAC returned {mac_len} bytes; expected 16"
                ))
            })
        })
    }
}
