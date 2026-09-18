use paysec_crypto_rustcrypto::RsaPublicKey;

use paysec_tr34::{KdhCredential, KrdCredential};

use rsa::pkcs8::DecodePublicKey;

const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/kdh-certificate.der");

const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/krd-certificate.der");

#[test]
fn parses_kdh_certificate_from_der() {
    assert!(KdhCredential::from_der(KDH_CERTIFICATE_DER,).is_ok());
}

#[test]
fn parses_krd_certificate_from_der() {
    assert!(KrdCredential::from_der(KRD_CERTIFICATE_DER,).is_ok());
}

#[test]
fn rejects_invalid_kdh_certificate_der() {
    assert!(KdhCredential::from_der(b"not a certificate",).is_err());
}

#[test]
fn rejects_invalid_krd_certificate_der() {
    assert!(KrdCredential::from_der(b"not a certificate",).is_err());
}

#[test]
fn exposes_krd_subject_public_key_info() {
    let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

    let spki = credential.subject_public_key_info_der().unwrap();

    assert!(!spki.is_empty());
}

#[test]
fn krd_public_key_can_be_imported_by_rustcrypto() {
    let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

    let spki = credential.subject_public_key_info_der().unwrap();

    RsaPublicKey::from_public_key_der(&spki).unwrap();
}
