use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{KeyType, ObjectClass};
use paysec_crypto::{RsaOaepSha256Encrypt, RsaPkcs1v15Sha256Sign, RsaPkcs1v15Sha256Verify};

use crate::object::resolve_key;
use crate::{Pkcs11Error, Pkcs11Key, Pkcs11Provider};

impl RsaOaepSha256Encrypt<Pkcs11Key> for Pkcs11Provider {
    fn encrypt_oaep_sha256(
        &mut self,
        key: &Pkcs11Key,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::PUBLIC_KEY, KeyType::RSA)?;

            let params = PkcsOaepParams::new(
                MechanismType::SHA256,
                PkcsMgfType::MGF1_SHA256,
                PkcsOaepSource::empty(),
            );

            let mechanism = Mechanism::RsaPkcsOaep(params);

            session
                .encrypt(&mechanism, key, plaintext)
                .map_err(|error| {
                    Pkcs11Error::cryptoki("failed to encrypt using RSA-OAEP-SHA256", error)
                })
        })
    }
}

impl RsaPkcs1v15Sha256Sign<Pkcs11Key> for Pkcs11Provider {
    fn sign_pkcs1v15_sha256(
        &self,
        key: &Pkcs11Key,
        message: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::PRIVATE_KEY, KeyType::RSA)?;

            session
                .sign(&Mechanism::Sha256RsaPkcs, key, message)
                .map_err(|error| {
                    Pkcs11Error::cryptoki("failed to sign using RSA-PKCS1-v1_5-SHA256", error)
                })
        })
    }
}

impl RsaPkcs1v15Sha256Verify<Pkcs11Key> for Pkcs11Provider {
    fn verify_pkcs1v15_sha256(
        &self,
        key: &Pkcs11Key,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        self.with_session(|session| {
            let key = resolve_key(session, key, ObjectClass::PUBLIC_KEY, KeyType::RSA)?;

            session
                .verify(&Mechanism::Sha256RsaPkcs, key, message, signature)
                .map_err(|error| {
                    Pkcs11Error::cryptoki("failed to verify RSA-PKCS1-v1_5-SHA256 signature", error)
                })
        })
    }
}
