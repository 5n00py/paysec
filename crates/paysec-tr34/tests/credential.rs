use paysec_tr34::KdhCredential;

const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/kdh-certificate.der");

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
fn rejects_invalid_kdh_certificate_der() {
    let result = KdhCredential::from_der(b"not a certificate");

    assert!(result.is_err());
}
