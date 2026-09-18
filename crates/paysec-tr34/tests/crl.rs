use paysec_tr34::KdhCrl;

const KDH_CRL_DER: &[u8] = include_bytes!("fixtures/kdh-crl.der");

#[test]
fn parses_kdh_crl_from_der() {
    KdhCrl::from_der(KDH_CRL_DER).unwrap();
}

#[test]
fn rejects_invalid_kdh_crl_der() {
    assert!(KdhCrl::from_der(b"not a crl",).is_err());
}
