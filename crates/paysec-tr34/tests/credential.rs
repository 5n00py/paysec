use paysec_tr34::{KdhCredential, KrdCredential};

const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/kdh-certificate.der");

const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/krd-certificate.der");

#[test]
fn parses_kdh_certificate_from_der() {
    let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

    assert!(
        !credential
            .certificate()
            .tbs_certificate
            .serial_number
            .as_bytes()
            .is_empty()
    );
}

#[test]
fn parses_krd_certificate_from_der() {
    let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

    assert!(
        !credential
            .certificate()
            .tbs_certificate
            .serial_number
            .as_bytes()
            .is_empty()
    );
}

#[test]
fn exposes_krd_subject_public_key_info() {
    let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

    let spki = credential.subject_public_key_info_der().unwrap();

    assert!(!spki.is_empty());
}

#[test]
fn rejects_invalid_kdh_certificate_der() {
    let result = KdhCredential::from_der(b"not a certificate");

    assert!(result.is_err());
}

#[test]
fn rejects_invalid_krd_certificate_der() {
    let result = KrdCredential::from_der(b"not a certificate");

    assert!(result.is_err());
}

use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};

#[test]
fn krd_public_key_can_be_imported_by_rustcrypto() {
    let credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

    let spki = credential.subject_public_key_info_der().unwrap();

    let public_key = RsaPublicKey::from_public_key_der(&spki).unwrap();

    use rsa::traits::PublicKeyParts;

    assert_eq!(public_key.size(), 256);
}
