use super::super::key_derivations::derive_keys_version_d;
use hex::decode as hex_decode;

#[test]
fn test_derive_keys_version_d_aes_128() {
    let kbpk = hex_decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let (kbek, kbak) = derive_keys_version_d(&kbpk).unwrap();

    assert_eq!(
        kbek,
        hex_decode("37DC7700D70781C3E2498A41A027E0B1").unwrap()
    );
    assert_eq!(
        kbak,
        hex_decode("063E785CE4C4C8FE54921839BD1F9ADF").unwrap()
    );
}

#[test]
fn test_derive_keys_version_d_aes_192() {
    let kbpk = hex_decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();
    let (kbek, kbak) = derive_keys_version_d(&kbpk).unwrap();

    assert_eq!(
        kbek,
        hex_decode("F343DFB92345457EF5CB08309EEB65DEC170BE7B069FB351").unwrap()
    );
    assert_eq!(
        kbak,
        hex_decode("23F93132F6677CD822FA653562F71CCE3CB9361733BFA128").unwrap()
    );
}

#[test]
fn test_derive_keys_version_d_aes_256() {
    let kbpk =
        hex_decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();
    let (kbek, kbak) = derive_keys_version_d(&kbpk).unwrap();

    assert_eq!(
        kbek,
        hex_decode("FCC7C7F7CA33DA31BA8C60493C7DD384C804C20EBA22022BC5AB29FEF42F20C7").unwrap()
    );
    assert_eq!(
        kbak,
        hex_decode("095DF0DCA65DC922BBEB015F8C855E254FD7CF399B6DA726ABA28206C9A7A3E2").unwrap()
    );
}

#[test]
fn test_derive_keys_version_d_a7422() {
    let kbpk =
        hex_decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();
    let (kbek, kbak) = derive_keys_version_d(&kbpk).unwrap();

    assert_eq!(
        kbek,
        hex_decode("396C9382A6E2E66A088774E1D6E46541F5EAD67D7204F8DD0D7AE8FDA334D3AC").unwrap()
    );
    assert_eq!(
        kbak,
        hex_decode("4EF24317696213840451890756757E573E0673483888F9B7F9B7517827F95022").unwrap()
    );
}
