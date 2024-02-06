use super::super::tr31::*;
use super::super::KeyBlockHeader;

#[test]
pub fn test_tr31_wrap_example_a_7_4() {
    // Test vectors from TR-31: 2018, A.7.4. Example 3
    let header = KeyBlockHeader::new_with_values("D", "P0", "A", "E", "00", "E").unwrap();
    let key = hex::decode("3F419E1CB7079442AA37474C2EFBF8B8").unwrap();
    let random_seed = hex::decode("1C2965473CE206BB855B01533782").unwrap();
    let masked_key_length = 16;
    let kbpk =
        hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}
