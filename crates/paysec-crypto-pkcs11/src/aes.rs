use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use paysec_crypto::{AesBlockCipher, AesCbc, AesCmac};

use zeroize::Zeroize;

use crate::object::resolve_key;
use crate::{Pkcs11Error, Pkcs11Key, Pkcs11Provider};

const AES_BLOCK_SIZE: usize = 16;
const AES_CMAC_SIZE: usize = 16;

/// Implements the raw AES block primitive using an opaque PKCS #11 AES key.
///
/// PKCS #11 exposes the raw AES block operation through `CKM_AES_ECB`.
/// `AesBlockCipher` operates on exactly one block, so this does not expose
/// general-purpose ECB mode to callers.
impl AesBlockCipher<Pkcs11Key> for Pkcs11Provider {
    fn encrypt_block(
        &self,
        key: &Pkcs11Key,
        block: &[u8; AES_BLOCK_SIZE],
    ) -> Result<[u8; AES_BLOCK_SIZE], Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            let output = session
                .encrypt(&Mechanism::AesEcb, key, block)
                .map_err(|error| Pkcs11Error::cryptoki("failed to encrypt AES block", error))?;

            aes_block_from_output(output, "encryption")
        })
    }

    fn decrypt_block(
        &self,
        key: &Pkcs11Key,
        block: &[u8; AES_BLOCK_SIZE],
    ) -> Result<[u8; AES_BLOCK_SIZE], Self::Error> {
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
) -> Result<[u8; AES_BLOCK_SIZE], Pkcs11Error> {
    let output_len = output.len();

    output.as_slice().try_into().map_err(|_| {
        Pkcs11Error::new(format!(
            "PKCS #11 AES block {operation} returned {output_len} bytes; \
             expected {AES_BLOCK_SIZE}"
        ))
    })
}

/// Implements AES-CBC using an existing opaque PKCS #11 AES key.
///
/// The key is resolved to a token or session object within the active
/// PKCS #11 session. No key material is read by the provider.
impl AesCbc<Pkcs11Key> for Pkcs11Provider {
    fn encrypt_cbc(
        &self,
        key: &Pkcs11Key,
        iv: &[u8; AES_BLOCK_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        validate_cbc_plaintext_length(plaintext)?;

        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            encrypt_cbc(session, key, iv, plaintext)
        })
    }

    fn decrypt_cbc(
        &self,
        key: &Pkcs11Key,
        iv: &[u8; AES_BLOCK_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        validate_cbc_ciphertext_length(ciphertext)?;

        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            decrypt_cbc(session, key, iv, ciphertext)
        })
    }
}

/// Implements AES-CMAC using an opaque PKCS #11 AES key.
///
/// PKCS #11 models MAC calculation through the signing interface, therefore
/// AES-CMAC is performed with `C_Sign` and `CKM_AES_CMAC`.
impl AesCmac<Pkcs11Key> for Pkcs11Provider {
    fn calculate_cmac(
        &self,
        key: &Pkcs11Key,
        message: &[u8],
    ) -> Result<[u8; AES_CMAC_SIZE], Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::SECRET_KEY, KeyType::AES)?;

            let mac = session
                .sign(&Mechanism::AesCMac, key, message)
                .map_err(|error| Pkcs11Error::cryptoki("failed to calculate AES-CMAC", error))?;

            let mac_len = mac.len();

            mac.as_slice().try_into().map_err(|_| {
                Pkcs11Error::new(format!(
                    "PKCS #11 AES-CMAC returned {mac_len} bytes; \
                     expected {AES_CMAC_SIZE}"
                ))
            })
        })
    }
}

/// Implements AES-CBC for host-resident AES key material.
///
/// Some higher-level protocols, such as the current TR-34 implementation,
/// intentionally create short-lived AES key material in application memory.
/// To keep the cryptographic operation inside PKCS #11, the key is imported
/// as a temporary session object, used for the operation, and immediately
/// destroyed.
///
/// The temporary object is never persisted because `CKA_TOKEN` is false.
impl AesCbc<[u8]> for Pkcs11Provider {
    fn encrypt_cbc(
        &self,
        key: &[u8],
        iv: &[u8; AES_BLOCK_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        validate_cbc_plaintext_length(plaintext)?;

        self.with_session(|session| {
            with_temporary_aes_key(session, key, |key| encrypt_cbc(session, key, iv, plaintext))
        })
    }

    fn decrypt_cbc(
        &self,
        key: &[u8],
        iv: &[u8; AES_BLOCK_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        validate_cbc_ciphertext_length(ciphertext)?;

        self.with_session(|session| {
            with_temporary_aes_key(session, key, |key| {
                decrypt_cbc(session, key, iv, ciphertext)
            })
        })
    }
}

fn encrypt_cbc(
    session: &Session,
    key: ObjectHandle,
    iv: &[u8; AES_BLOCK_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, Pkcs11Error> {
    session
        .encrypt(&Mechanism::AesCbc(*iv), key, plaintext)
        .map_err(|error| Pkcs11Error::cryptoki("failed to encrypt AES-CBC data", error))
}

fn decrypt_cbc(
    session: &Session,
    key: ObjectHandle,
    iv: &[u8; AES_BLOCK_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Pkcs11Error> {
    session
        .decrypt(&Mechanism::AesCbc(*iv), key, ciphertext)
        .map_err(|error| Pkcs11Error::cryptoki("failed to decrypt AES-CBC data", error))
}

fn validate_cbc_plaintext_length(plaintext: &[u8]) -> Result<(), Pkcs11Error> {
    if plaintext.len() % AES_BLOCK_SIZE != 0 {
        return Err(Pkcs11Error::new(
            "AES-CBC plaintext length must be a multiple of 16 bytes",
        ));
    }

    Ok(())
}

fn validate_cbc_ciphertext_length(ciphertext: &[u8]) -> Result<(), Pkcs11Error> {
    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(Pkcs11Error::new(
            "AES-CBC ciphertext length must be a multiple of 16 bytes",
        ));
    }

    Ok(())
}

/// Creates an AES session object from host-resident key material.
///
/// The object is explicitly non-persistent (`CKA_TOKEN = false`) and
/// non-extractable. The copy of the key stored in the PKCS #11 attribute
/// template is wiped immediately after `C_CreateObject` returns.
fn create_temporary_aes_key(session: &Session, key: &[u8]) -> Result<ObjectHandle, Pkcs11Error> {
    validate_aes_key_length(key.len())?;

    let mut template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Value(key.to_vec()),
    ];

    let result = session.create_object(&template);

    // C_CreateObject is synchronous. Once it returns, the PKCS #11
    // implementation has consumed the template, so wipe our temporary
    // host-memory copy of the key before processing the result.
    for attribute in &mut template {
        if let Attribute::Value(value) = attribute {
            value.zeroize();
        }
    }

    result.map_err(|error| {
        Pkcs11Error::cryptoki("failed to create temporary PKCS #11 AES key", error)
    })
}

/// Executes an operation using a temporary AES session object.
///
/// Destruction is attempted regardless of whether the cryptographic
/// operation succeeds. Session objects would also disappear when the
/// session closes, but the provider keeps its session open for its lifetime,
/// so temporary keys must be destroyed eagerly.
fn with_temporary_aes_key<T>(
    session: &Session,
    key: &[u8],
    operation: impl FnOnce(ObjectHandle) -> Result<T, Pkcs11Error>,
) -> Result<T, Pkcs11Error> {
    let key_handle = create_temporary_aes_key(session, key)?;

    let operation_result = operation(key_handle);

    let destroy_result = session.destroy_object(key_handle).map_err(|error| {
        Pkcs11Error::cryptoki("failed to destroy temporary PKCS #11 AES key", error)
    });

    match (operation_result, destroy_result) {
        (Ok(value), Ok(())) => Ok(value),

        (Err(error), Ok(())) => Err(error),

        (Ok(_), Err(error)) => Err(error),

        (Err(operation_error), Err(destroy_error)) => Err(Pkcs11Error::new(format!(
            "{operation_error}; additionally failed to destroy \
                 temporary PKCS #11 AES key: {destroy_error}"
        ))),
    }
}

fn validate_aes_key_length(length: usize) -> Result<(), Pkcs11Error> {
    match length {
        16 | 24 | 32 => Ok(()),
        _ => Err(Pkcs11Error::invalid_aes_key_length(length)),
    }
}
