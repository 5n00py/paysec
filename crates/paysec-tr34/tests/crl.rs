use paysec_tr34::{KdhCredential, KdhCrl};

const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("fixtures/kdh-certificate.der");

const KDH_CRL_DER: &[u8] = include_bytes!("fixtures/kdh-crl.der");

#[test]
fn parses_kdh_crl_from_der() {
    KdhCrl::from_der(KDH_CRL_DER).unwrap();
}

#[test]
fn rejects_invalid_kdh_crl_der() {
    assert!(KdhCrl::from_der(b"not a crl").is_err());
}

#[test]
fn kdh_crl_issuer_matches_kdh_certificate_issuer() {
    let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

    let crl = KdhCrl::from_der(KDH_CRL_DER).unwrap();

    assert_eq!(
        crl.certificate_list().tbs_cert_list.issuer,
        credential.certificate().tbs_certificate.issuer
    );
}
