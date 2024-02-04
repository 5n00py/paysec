use crate::keyblock::*;

#[test]
fn test_new_empty() {
    let header = KeyBlockHeader::new_empty();
    assert_eq!(header.version_id(), "");
    assert_eq!(header.kb_length(), 0);
    assert_eq!(header.key_usage(), "");
    assert_eq!(header.algorithm(), "");
    assert_eq!(header.mode_of_use(), "");
    assert_eq!(header.key_version_number(), "");
    assert_eq!(header.exportability(), "");
    assert_eq!(header.num_optional_blocks(), 0);
    assert_eq!(header.reserved_field(), "00");
}

#[test]
fn test_new_with_values() {
    let header = KeyBlockHeader::new_with_values("B", "B1", "D", "S", "01", "E").unwrap();
    assert_eq!(header.version_id(), "B");
    assert_eq!(header.key_usage(), "B1");
    assert_eq!(header.algorithm(), "D");
    assert_eq!(header.mode_of_use(), "S");
    assert_eq!(header.key_version_number(), "01");
    assert_eq!(header.exportability(), "E");
}

#[test]
fn test_new_with_values_invalid_params() {
    let res = KeyBlockHeader::new_with_values("X", "B0", "A", "B", "01", "E");
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid version ID: X"
    );

    let res = KeyBlockHeader::new_with_values("B", "XX", "A", "B", "01", "E");
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid key usage: XX"
    );

    let res = KeyBlockHeader::new_with_values("B", "B0", "X", "B", "01", "E");
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid algorithm: X"
    );

    let res = KeyBlockHeader::new_with_values("B", "B0", "A", "Z", "01", "E");
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid mode of use: Z"
    );

    let res = KeyBlockHeader::new_with_values("B", "B0", "A", "B", "X", "E");
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Key version number must consist of 2 ASCII characters: X"
    );

    let res = KeyBlockHeader::new_with_values("B", "B0", "A", "B", "01", "X");
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid exportability: X"
    );
}

#[test]
fn test_new_from_str() {
    let header = KeyBlockHeader::new_from_str("B0000B1DB00N0000").unwrap();
    assert_eq!(header.version_id(), "B");
    assert_eq!(header.kb_length(), 0);
    assert_eq!(header.key_usage(), "B1");
    assert_eq!(header.algorithm(), "D");
    assert_eq!(header.mode_of_use(), "B");
    assert_eq!(header.key_version_number(), "00");
    assert_eq!(header.exportability(), "N");
    assert_eq!(header.num_optional_blocks(), 0);
    assert_eq!(header.reserved_field(), "00");
}

#[test]
fn test_new_from_str_with_optional_block() {
    // Sample header string with an optional block
    // Adjust the string to fit the expected format and length
    let header_str = "B0160B1DB00N0100CT0C11223344"; // Example string
    let result = KeyBlockHeader::new_from_str(header_str).unwrap();

    // Assert the main header fields
    assert_eq!(result.version_id(), "B");
    assert_eq!(result.kb_length(), 160);
    assert_eq!(result.key_usage(), "B1");
    assert_eq!(result.algorithm(), "D");
    assert_eq!(result.mode_of_use(), "B");
    assert_eq!(result.key_version_number(), "00");
    assert_eq!(result.exportability(), "N");
    assert_eq!(result.num_optional_blocks(), 1);
    assert_eq!(result.reserved_field(), "00");
    assert_eq!(result.header_length(), 28);

    // Assert the optional block
    let opt_block_ref = result.opt_blocks().as_ref().unwrap();
    assert_eq!(opt_block_ref.id(), "CT");
    assert_eq!(opt_block_ref.data(), "11223344");
}

#[test]
fn test_new_from_str_invalid_length() {
    let result = KeyBlockHeader::new_from_str("TooShort");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid data length"
    );
}

#[test]
fn test_new_from_str_invalid_key_block_length() {
    let result = KeyBlockHeader::new_from_str("BXXXXB1DB00N0000");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid key block length"
    );
}

#[test]
fn test_new_from_str_invalid_number_of_optional_blocks() {
    let result = KeyBlockHeader::new_from_str("B0000B1DB00NXX00");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid number of optional blocks"
    );
}

// #[test]
// fn test_new_from_str_invalid_header_length_with_optional_blocks() {
//     let header_str = "B0010B1DB00N0200Short";
//     let result = KeyBlockHeader::new_from_str(header_str);
//     assert!(result.is_err());
//     assert_eq!(
//         result.err().unwrap().to_string(),
//         "ERROR TR-31 HEADER: Invalid header length containing optional blocks"
//     );
// }
//
#[test]
fn test_new_from_str_failed_to_parse_optional_blocks() {
    let header_str = "B0010B1DB00N0200InvalidOptBlockData";
    let result = KeyBlockHeader::new_from_str(header_str);
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().to_string(), "ERROR TR-31 HEADER: Failed to parse optional blocks: ERROR TR-31 OPT BLOCK: Invalid ID: In");
}

#[test]
fn test_new_from_str_invalid_header_length_with_optional_blocks() {
    let header_str = "B0016B1DB00N0100";

    match KeyBlockHeader::new_from_str(header_str) {
        Err(e) => assert_eq!(
            e.to_string(),
            "ERROR TR-31 HEADER: Invalid header length containing optional blocks"
        ),
        Ok(_) => panic!("Expected an error due to inconsistent header length, but got Ok"),
    }
}

#[test]
fn test_set_version_id() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_version_id("B").unwrap();
    assert_eq!(header.version_id(), "B");

    let result = header.set_version_id("E");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid version ID: E"
    );
}

#[test]
fn test_set_kb_length() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_kb_length(100).unwrap();
    assert_eq!(header.kb_length(), 100);

    let result = header.set_kb_length(10000);
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid key block length"
    );
}

#[test]
fn test_set_key_usage() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_key_usage("B1").unwrap();
    assert_eq!(header.key_usage(), "B1");

    let result = header.set_key_usage("ZZ");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid key usage: ZZ"
    );
}

#[test]
fn test_set_algorithm() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_algorithm("D").unwrap();
    assert_eq!(header.algorithm(), "D");

    let result = header.set_algorithm("Z");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid algorithm: Z"
    );
}

#[test]
fn test_set_mode_of_use() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_mode_of_use("B").unwrap();
    assert_eq!(header.mode_of_use(), "B");

    let result = header.set_mode_of_use("Z");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid mode of use: Z"
    );
}

#[test]
fn test_set_key_version_number() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_key_version_number("01").unwrap();
    assert_eq!(header.key_version_number(), "01");

    let result = header.set_key_version_number("1");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Key version number must consist of 2 ASCII characters: 1"
    );

    let result = header.set_key_version_number("010");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Key version number must consist of 2 ASCII characters: 010"
    );
}

#[test]
fn test_set_key_version_number_non_ascii_error() {
    let mut header = KeyBlockHeader::new_empty();
    let non_ascii_value = "ÿ";

    match header.set_key_version_number(non_ascii_value) {
        Err(e) => assert_eq!(
            e.to_string(),
            format!(
                "ERROR TR-31 HEADER: Key version number must consist of ASCII characters: {}",
                non_ascii_value
            )
        ),
        Ok(_) => panic!("Expected an error for non-ASCII key version number, but got Ok"),
    }
}

#[test]
fn test_set_exportability() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_exportability("N").unwrap();
    assert_eq!(header.exportability(), "N");

    let result = header.set_exportability("Z");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid exportability: Z"
    );
}

#[test]
fn test_set_num_optional_blocks() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_num_optional_blocks(99).unwrap();
    assert_eq!(header.num_optional_blocks(), 99);

    let result = header.set_num_optional_blocks(100);
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Number of opt blocks value is too large"
    );
}

#[test]
fn test_set_reserved_field() {
    let mut header = KeyBlockHeader::new_empty();
    header.set_reserved_field("00").unwrap();
    assert_eq!(header.reserved_field(), "00");

    let result = header.set_reserved_field("01");
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "ERROR TR-31 HEADER: Invalid value for reserved field: 01"
    );
}

#[test]
fn test_set_reserved_field_invalid_value_error() {
    let mut header = KeyBlockHeader::new_empty();
    let invalid_value = "01"; // An example of an invalid value

    match header.set_reserved_field(invalid_value) {
        Err(e) => assert_eq!(
            e.to_string(),
            format!(
                "ERROR TR-31 HEADER: Invalid value for reserved field: {}",
                invalid_value
            )
        ),
        Ok(_) => panic!("Expected an error for invalid reserved field value, but got Ok"),
    }
}
