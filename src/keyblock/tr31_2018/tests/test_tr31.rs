use super::super::tr31::*;
use super::super::KeyBlockHeader;
use super::super::OptBlock;

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

#[test]
pub fn test_tr31_wrap_example_aes_128() {
    // AES-128 KBPK, no optional blocks, no masked length
    let header = KeyBlockHeader::new_with_values("D", "P0", "T", "E", "00", "N").unwrap();
    let key = hex::decode("AABBCCDDEEFFAABB").unwrap();
    let random_seed = hex::decode("475B1C029B79A6D5DBD53D3A6E2BA79AF3AEB461BE03").unwrap();
    let masked_key_length = 16; // No masked length in this case
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0112P0TE00N00000CB35E3A9DC6CE21DF5FC9D04F5645529183FA41CEC5253E42AEF6061C67BFA4271B7369364F5222C8FC258F52296C9D";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_128_masked_length() {
    // AES-128 KBPK, no optional blocks, masked length
    let header = KeyBlockHeader::new_with_values("D", "P0", "T", "E", "00", "N").unwrap();
    let key = hex::decode("AABBCCDDEEFF").unwrap();
    let masked_key_length = 32; // Specified masked length
    let random_seed = hex::decode(
        "2017D166DA60F47B32365F3D47BE283A629E83F9804E36B1EA44AF1B7C5BD99E56C858CDCBF054CC",
    )
    .unwrap();
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0144P0TE00N000093D359E5069E5FCBEEA844135E4286AC10C18989BBE102F8870D7852E20AC255413F326C7855C71B9A85B9F8F52AD7EA296B271EC8EDA37453D20659C01D4229";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_128_two_optional_blocks() {
    // AES-128 KBPK, two optional blocks, zero masked length
    let mut header = KeyBlockHeader::new_with_values("D", "P0", "T", "E", "00", "N").unwrap();
    header.set_num_optional_blocks(2).unwrap();

    // Add the first optional block
    let mut opt_block1 = OptBlock::new("KS", "00604B120F9292800000", None).unwrap();
    // Add the second optional block
    let opt_block2 = OptBlock::new("PB", "0000", None).unwrap();
    opt_block1.set_next(Some(opt_block2));
    header.set_opt_blocks(Some(Box::new(opt_block1)));

    let key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();
    let masked_key_length = 0; // No masked length
    let random_seed = hex::decode("DDCAA6156A32D4A2734F9AF8A06A").unwrap();
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB0800008C33D790E39C605B6966CB81E79ADBDFEF1341850A655F383783CB17F64E3D3E0901DC80A564B8365F0979A06904FEEA";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_192_no_optional_blocks() {
    // AES-192 KBPK, no optional blocks, no masked length
    let header = KeyBlockHeader::new_with_values("D", "P0", "T", "E", "00", "N").unwrap();
    let key = hex::decode("AABBCCDDEEFFAABB").unwrap();
    let masked_key_length = 24; // Using AES-192 KBPK length as masked length
    let random_seed = hex::decode("34F9A6D81322D5E840681B31C582164233334F7A3A1E").unwrap();
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0112P0TE00N0000881D0564A76673B02399370A2325C951FA3F8ED1AD80F0B34E5A7043802D5FF2C7C7386F1D145A7287227C072AD59135";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_192_no_optional_blocks_masked_length() {
    // AES-192 KBPK, no optional blocks, masked length
    let header = KeyBlockHeader::new_with_values("D", "B1", "T", "E", "00", "N").unwrap();
    let key = hex::decode("AABBCCDDEEFF").unwrap();
    let masked_key_length = 32;
    let random_seed = hex::decode(
        "6F29166EBED03C18039729F353FBCE3604A02FBF1BBB4BFDBFDD2E9296CEBFDE2641DDEA68D5FAD4",
    )
    .unwrap();
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0144B1TE00N00001CF87C5209D461283FAA104730F9A2B13B6DDEE609EECE848C61EF2CAFA48125BA0606C623FAB58D9B7CD820AB20935980478542F7C26DB42F11F3AA89FA9332";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_192_two_optional_blocks() {
    // AES-192 KBPK, two optional blocks, zero masked length
    let header =
        KeyBlockHeader::new_from_str("D0048P0TE00N0200KS1800604B120F9292800000PB080000").unwrap();
    let key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();
    let masked_key_length = 0;
    let random_seed = hex::decode("223655F4BC798073D74B705B9FFB").unwrap();
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB080000F2A795BB540447553D9FA3812E64E76A577DA04A1E0DD9FA9EFDE394BE936D4532BF5BA7E57063B63FCD90F9C2020F77";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_192_one_optional_block_finalized() {
    // AES-192 KBPK, one optional blocks, zero masked length
    let mut header =
        KeyBlockHeader::new_from_str("D0048P0TE00N0100KS1800604B120F9292800000").unwrap();
    // Add padding block
    header.finalize().unwrap();
    let key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();
    let masked_key_length = 0;
    let random_seed = hex::decode("223655F4BC798073D74B705B9FFB").unwrap();
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB080000F2A795BB540447553D9FA3812E64E76A577DA04A1E0DD9FA9EFDE394BE936D4532BF5BA7E57063B63FCD90F9C2020F77";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_256_no_optional_blocks_no_masked_length() {
    // AES-256 KBPK, no optional blocks, no masked length
    let header = KeyBlockHeader::new_with_values("D", "P0", "T", "E", "00", "N").unwrap();
    let key = hex::decode("AABBCCDDEEFFAABBAABBCCDDEEFFAABB").unwrap();
    let random_seed = hex::decode("F13420DA9829ED30B6DDA8FA88C4").unwrap();
    let masked_key_length = 0; // No masked length
    let kbpk =
        hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0112P0TE00N0000E06A6D9B1FA5E7566A7AA874609D7F5790EA3512AE1E671299767ADD2FD32AAE8C4D7284B32846405F6FB8546591371A";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_256_no_optional_blocks_masked_length() {
    // AES-256 KBPK, no optional blocks, masked length
    let header = KeyBlockHeader::new_with_values("D", "B1", "T", "E", "00", "N").unwrap();
    let key =
        hex::decode("AABBCCDDEEFFAABBAABBCCDDEEFFAABBAABBCCDDEEFFAABBAABBCCDDEEFFAABB").unwrap();
    let masked_key_length = 64;
    let random_seed = hex::decode("F93271EC6B8E1BD97A9212B0FBDD99A29F8E3B0C655F59D90C039A9D371CEBB01E38BA78196EEA544BD077849344").unwrap();
    let kbpk =
        hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0208B1TE00N0000F34BCC63BD9EB2A670220DE516F9A6E6A701FC3843E52E232FC22FF4FC41E3B076D7E0AF1AA62DD968281A0F64AEC2A43586841472F93C17C1FAF68D06BC1B5C64890597D46D2BA663962217D18EA412092E1A5DED1B858A378385FA64E4EF63";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_example_aes_256_two_optional_blocks() {
    // AES-256 KBPK, two optional blocks, zero masked length
    let header =
        KeyBlockHeader::new_from_str("D0048P0TE00N0200KS1800604B120F9292800000PB080000").unwrap();
    let key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();
    let random_seed = hex::decode("7338958D82B9F482E421E8BFD77E").unwrap();
    let masked_key_length = 0;
    let kbpk =
        hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();

    let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();

    let expected_key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB080000BB07D34B055CF948CD3FB0C9D55AC064F32D855EBC0AE666E49C6393BC4EA33B356E735F1BEE0612C6E80A5DAB7B9BCA";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
fn test_tr31_wrap_error_key_block_length_not_multiple_of_block_size() {
    let header =
        KeyBlockHeader::new_from_str("D0048P0TE00N0200KS1800604B120F9292800000PB0600").unwrap();
    let key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();
    let masked_key_length = 0;
    let random_seed = hex::decode("223655F4BC798073D74B705B9FFB").unwrap();
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();

    let result = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed);

    assert!(matches!(
        result,
        Err(e) if e.to_string() == "ERROR TR-31: Total block length is not a multiple of block length: 16"
    ));
}

#[test]
pub fn test_tr31_unwrap_example_a_7_4() {
    // Key Block from the wrapping test
    let key_block = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";

    // Key Block Protection Key
    let kbpk =
        hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();

    // Expected key that should be extracted
    let expected_key = hex::decode("3F419E1CB7079442AA37474C2EFBF8B8").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();

    // Assert that the extracted key matches the expected key
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "P0", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "A", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        0,
        "Header number of optional blocks mismatch"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_128() {
    // Key Block from the wrapping test
    let key_block = "D0112P0TE00N00000CB35E3A9DC6CE21DF5FC9D04F5645529183FA41CEC5253E42AEF6061C67BFA4271B7369364F5222C8FC258F52296C9D";

    // Key Block Protection Key
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

    // Expected key that should be extracted
    let expected_key = hex::decode("AABBCCDDEEFFAABB").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();

    // Assert that the extracted key matches the expected key
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "P0", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        0,
        "Header should have no optional blocks"
    );

    // Since there are no optional blocks, opt_blocks should be None
    assert!(
        header.opt_blocks().is_none(),
        "Header should not have optional blocks"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_128_masked_length() {
    // Key Block from the wrapping test
    let key_block = "D0144P0TE00N000093D359E5069E5FCBEEA844135E4286AC10C18989BBE102F8870D7852E20AC255413F326C7855C71B9A85B9F8F52AD7EA296B271EC8EDA37453D20659C01D4229";

    // Key Block Protection Key
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

    // Expected key that should be extracted
    let expected_key = hex::decode("AABBCCDDEEFF").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();

    // Assert that the extracted key matches the expected key
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "P0", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        0,
        "Header should have no optional blocks"
    );

    // Since there are no optional blocks, opt_blocks should be None
    assert!(
        header.opt_blocks().is_none(),
        "Header should not have optional blocks"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_128_two_optional_blocks() {
    // Key Block from the wrapping test
    let key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB0800008C33D790E39C605B6966CB81E79ADBDFEF1341850A655F383783CB17F64E3D3E0901DC80A564B8365F0979A06904FEEA";

    // Key Block Protection Key
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

    // Expected key that should be extracted
    let expected_key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();

    // Assert that the extracted key matches the expected key
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "P0", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        2,
        "Header should have two optional blocks"
    );

    // Assert the contents of the optional blocks
    let opt_blocks = header.opt_blocks().clone().unwrap();
    let first_opt_block = opt_blocks.as_ref();
    assert_eq!(
        first_opt_block.id(),
        "KS",
        "First optional block ID mismatch"
    );
    assert_eq!(
        first_opt_block.data(),
        "00604B120F9292800000",
        "First optional block data mismatch"
    );

    let second_opt_block = first_opt_block.next().unwrap();
    assert_eq!(
        second_opt_block.id(),
        "PB",
        "Second optional block ID mismatch"
    );
    assert_eq!(
        second_opt_block.data(),
        "0000",
        "Second optional block data mismatch"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_192_no_optional_blocks_masked_length() {
    let key_block = "D0144B1TE00N00001CF87C5209D461283FAA104730F9A2B13B6DDEE609EECE848C61EF2CAFA48125BA0606C623FAB58D9B7CD820AB20935980478542F7C26DB42F11F3AA89FA9332";
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();
    let expected_key = hex::decode("AABBCCDDEEFF").unwrap();

    let unwrap_result = tr31_unwrap(&kbpk, key_block);
    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "B1", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        0,
        "Header should have no optional blocks"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_192_two_optional_blocks() {
    let key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB080000F2A795BB540447553D9FA3812E64E76A577DA04A1E0DD9FA9EFDE394BE936D4532BF5BA7E57063B63FCD90F9C2020F77";
    let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();
    let expected_key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();

    let unwrap_result = tr31_unwrap(&kbpk, key_block);
    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "P0", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        2,
        "Header should have two optional blocks"
    );

    // Assert the contents of the optional blocks
    let opt_blocks = header.opt_blocks().clone().unwrap();
    let first_opt_block = opt_blocks.as_ref();
    assert_eq!(
        first_opt_block.id(),
        "KS",
        "First optional block ID mismatch"
    );
    assert_eq!(
        first_opt_block.data(),
        "00604B120F9292800000",
        "First optional block data mismatch"
    );

    let second_opt_block = first_opt_block.next().unwrap();
    assert_eq!(
        second_opt_block.id(),
        "PB",
        "Second optional block ID mismatch"
    );
    assert_eq!(
        second_opt_block.data(),
        "0000",
        "Second optional block data mismatch"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_256_no_optional_blocks_no_masked_length() {
    let key_block = "D0112P0TE00N0000E06A6D9B1FA5E7566A7AA874609D7F5790EA3512AE1E671299767ADD2FD32AAE8C4D7284B32846405F6FB8546591371A";
    let kbpk =
        hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();
    let expected_key = hex::decode("AABBCCDDEEFFAABBAABBCCDDEEFFAABB").unwrap();

    let unwrap_result = tr31_unwrap(&kbpk, key_block);
    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "P0", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        0,
        "Header should have no optional blocks"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_256_no_optional_blocks_masked_length() {
    let key_block = "D0208B1TE00N0000F34BCC63BD9EB2A670220DE516F9A6E6A701FC3843E52E232FC22FF4FC41E3B076D7E0AF1AA62DD968281A0F64AEC2A43586841472F93C17C1FAF68D06BC1B5C64890597D46D2BA663962217D18EA412092E1A5DED1B858A378385FA64E4EF63";
    let kbpk =
        hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();
    let expected_key =
        hex::decode("AABBCCDDEEFFAABBAABBCCDDEEFFAABBAABBCCDDEEFFAABBAABBCCDDEEFFAABB").unwrap();

    let unwrap_result = tr31_unwrap(&kbpk, key_block);
    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "B1", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        0,
        "Header should have no optional blocks"
    );
}

#[test]
pub fn test_tr31_unwrap_example_aes_256_two_optional_blocks() {
    let key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB080000BB07D34B055CF948CD3FB0C9D55AC064F32D855EBC0AE666E49C6393BC4EA33B356E735F1BEE0612C6E80A5DAB7B9BCA";
    let kbpk =
        hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();
    let expected_key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();

    let unwrap_result = tr31_unwrap(&kbpk, key_block);
    assert!(unwrap_result.is_ok(), "Unwrapping failed");

    let (header, extracted_key) = unwrap_result.unwrap();
    assert_eq!(extracted_key, expected_key, "Extracted key mismatch");

    // Assert header fields
    assert_eq!(header.version_id(), "D", "Header version ID mismatch");
    assert_eq!(header.key_usage(), "P0", "Header key usage mismatch");
    assert_eq!(header.algorithm(), "T", "Header algorithm mismatch");
    assert_eq!(header.mode_of_use(), "E", "Header mode of use mismatch");
    assert_eq!(
        header.key_version_number(),
        "00",
        "Header key version number mismatch"
    );
    assert_eq!(header.exportability(), "N", "Header exportability mismatch");
    assert_eq!(
        header.num_optional_blocks(),
        2,
        "Header should have two optional blocks"
    );

    // Assert the contents of the optional blocks
    let opt_blocks = header.opt_blocks().clone().unwrap();
    let first_opt_block = opt_blocks.as_ref();
    assert_eq!(
        first_opt_block.id(),
        "KS",
        "First optional block ID mismatch"
    );
    assert_eq!(
        first_opt_block.data(),
        "00604B120F9292800000",
        "First optional block data mismatch"
    );

    let second_opt_block = first_opt_block.next().unwrap();
    assert_eq!(
        second_opt_block.id(),
        "PB",
        "Second optional block ID mismatch"
    );
    assert_eq!(
        second_opt_block.data(),
        "0000",
        "Second optional block data mismatch"
    );
}

#[test]
pub fn test_tr31_wrap_with_header_string_example_a_7_4() {
    // Test vectors from TR-31: 2018, A.7.4. Example 3
    let header_str = "D0144P0AE00E0000";
    let key = hex::decode("3F419E1CB7079442AA37474C2EFBF8B8").unwrap();
    let random_seed = hex::decode("1C2965473CE206BB855B01533782").unwrap();
    let masked_key_length = 16;
    let kbpk =
        hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();

    let key_block =
        tr31_wrap_with_header_string(header_str, &kbpk, &key, masked_key_length, &random_seed)
            .unwrap();

    let expected_key_block = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_wrap_with_header_string_example_aes_256_two_optional_blocks() {
    // AES-256 KBPK, two optional blocks, zero masked length
    let header_str = "D0000P0TE00N0200KS1800604B120F9292800000PB080000";
    let key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();
    let random_seed = hex::decode("7338958D82B9F482E421E8BFD77E").unwrap();
    let masked_key_length = 0;
    let kbpk =
        hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap();

    let key_block =
        tr31_wrap_with_header_string(header_str, &kbpk, &key, masked_key_length, &random_seed)
            .unwrap();

    let expected_key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB080000BB07D34B055CF948CD3FB0C9D55AC064F32D855EBC0AE666E49C6393BC4EA33B356E735F1BEE0612C6E80A5DAB7B9BCA";
    assert_eq!(key_block, expected_key_block, "Complete key block mismatch");
}

#[test]
pub fn test_tr31_unwrap_wrong_key_block_length() {
    // Key Block from the wrapping test
    let key_block = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC";

    // Key Block Protection Key
    let kbpk =
        hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(
        unwrap_result.is_err(),
        "Unwrapping should fail due to wrong key block length"
    );
}

#[test]
pub fn test_tr31_unwrap_wrong_mac() {
    // Key Block from the wrapping test
    let key_block = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC33";

    // Key Block Protection Key
    let kbpk =
        hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(
        unwrap_result.is_err(),
        "Unwrapping should fail due to wrong MAC"
    );
}

#[test]
pub fn test_tr31_unwrap_wrong_minimum_length() {
    // Key Block from the wrapping test
    let key_block = "D0144P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";

    // Key Block Protection Key
    let kbpk =
        hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(
        unwrap_result.is_err(),
        "Unwrapping should fail due to wrong minimum length"
    );
}

#[test]
pub fn test_tr31_unwrap_unsupported_version() {
    // Key Block from the wrapping test
    let key_block = "A0144P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";

    // Key Block Protection Key
    let kbpk =
        hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();

    // Perform the unwrapping
    let unwrap_result = tr31_unwrap(&kbpk, key_block);

    assert!(
        unwrap_result.is_err(),
        "Unwrapping should fail due to wrong version"
    );
}
