use crate::keyblock::*;
use std::fmt::Write;

#[test]
fn test_new_empty_creates_empty_opt_block() {
    let opt_block = OptBlock::new_empty();

    assert!(opt_block.id().is_empty(), "ID should be empty");
    assert!(opt_block.data().is_empty(), "Data should be empty");
    assert_eq!(*opt_block.length(), 0, "Length should be 0");
    assert!(opt_block.next().is_none(), "Next should be None");
}

#[test]
fn test_new_with_values() {
    // Test creating an OptBlock without a next block
    let opt_block_1 = OptBlock::new("PB", "FFFF", None);
    assert!(opt_block_1.is_ok());
    let opt_block_1 = opt_block_1.unwrap();
    assert_eq!(opt_block_1.id(), "PB");
    assert_eq!(opt_block_1.data(), "FFFF");
    assert_eq!(*opt_block_1.length(), 8);
    assert!(opt_block_1.next().is_none());

    // Test creating another OptBlock with opt_block_1 as the next block
    let opt_block_1_copy = opt_block_1.clone(); // Clone opt_block_1 before it is moved
    let opt_block_2 = OptBlock::new("CT", "1234", Some(opt_block_1));
    assert!(opt_block_2.is_ok());
    let opt_block_2 = opt_block_2.unwrap();
    assert_eq!(opt_block_2.id(), "CT");
    assert_eq!(opt_block_2.data(), "1234");
    assert_eq!(*opt_block_2.length(), 8);
    assert_eq!(*opt_block_2.next().unwrap(), opt_block_1_copy);
}

#[test]
fn test_new_with_values_invalid_id() {
    let opt_block = OptBlock::new("xx", "FFFF", None);
    assert!(opt_block.is_err());
    let error = opt_block.err().unwrap();

    // Optionally check the error message
    assert_eq!(error.to_string(), "ERROR TR-31 OPT BLOCK: Invalid ID: xx");
}

#[test]
fn test_new_with_values_invalid_data() {
    let opt_block = OptBlock::new("PB", "ÿÿÿÿ", None);
    assert!(opt_block.is_err());
    let error = opt_block.err().unwrap();

    // Optionally check the error message
    assert_eq!(
        error.to_string(),
        "ERROR TR-31 OPT BLOCK: Data has non ASCII characters: ÿÿÿÿ"
    );
}

#[test]
fn test_new_from_string_one_optional_block() {
    let s = "CT0C11223344";
    let num_opt_blocks = 1;
    let expected_opt_block = OptBlock::new("CT", "11223344", None).unwrap();
    let result = OptBlock::new_from_str(s, num_opt_blocks).unwrap();
    assert_eq!(result, expected_opt_block);
}

#[test]
fn test_new_from_string_two_optional_blocks() {
    let s = "CT0C11223344HM0E5566778899";
    let num_opt_blocks = 2;
    let mut expected_block1 = OptBlock::new("CT", "11223344", None).unwrap();
    let expected_block2 = OptBlock::new("HM", "5566778899", None).unwrap();
    expected_block1.set_next(Some(expected_block2));
    let result = OptBlock::new_from_str(s, num_opt_blocks).unwrap();
    assert_eq!(result, expected_block1);
}

#[test]
fn test_new_from_string_extended_optional_block() {
    let mut s = "CT00020100".to_owned();
    let data = "F".repeat(246);
    s += &data;
    let num_opt_blocks = 1;
    let expected_opt_block = OptBlock::new("CT", &data, None).unwrap();
    let result = OptBlock::new_from_str(&s, num_opt_blocks).unwrap();
    assert_eq!(result, expected_opt_block);
}

#[test]
fn test_new_from_string_invalid_empty_string() {
    let s = "";
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(s, num_opt_blocks);
    assert!(result.is_err());
    let error = result.err().unwrap();
    assert_eq!(
        error.to_string(),
        "ERROR TR-31 OPT BLOCK: String too short. Expected at least 4 characters"
    );
}

#[test]
fn test_new_from_string_invalid_length() {
    let s = "CT";
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: String too short. Expected at least 4 characters"
    );
}

#[test]
fn test_new_from_string_invalid_id() {
    let s = "xx081234";
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: Invalid ID: xx"
    );
}

#[test]
fn test_new_from_string_invalid_extended_length() {
    let s = "CT0002FFFFABCD";
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "ERROR TR-31 OPT BLOCK: String containing extended length too short. Expected at least 256 characters");
}

#[test]
fn test_new_from_string_invalid_length_field() {
    let s = "CTxx";
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: Invalid length field: 'xx' is not a valid hexadecimal number"
    );
}

#[test]
fn test_new_from_string_invalid_length_of_length() {
    let mut s = "CT00010000".to_owned();
    let to_append = "1CEDCAFFE1A77E".repeat(100);
    s += &to_append;
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(&s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: Invalid length of length field: 01"
    );
}

#[test]
fn test_new_from_string_invalid_extended_length_field() {
    let mut s = "CT00020000".to_owned();
    let to_append = "1CEDCAFFE1A77E".repeat(100);
    s += &to_append;
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(&s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: Extended length is not greater than 255: 0000"
    );
}

#[test]
fn test_new_from_string_invalid_data_length() {
    let s = "CT0800";
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: String too short for given length. Expected at least 8 characters."
    );
}

#[test]
fn test_new_from_string_invalid_extended_length_too_short() {
    let mut s = "CT000200A0".to_owned();
    let to_append = "1CEDCAFFE1A77E".repeat(100);
    s += &to_append;
    let num_opt_blocks = 1;
    let result = OptBlock::new_from_str(&s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: Extended length is not greater than 255: 00A0"
    );
}

#[test]
fn test_new_from_string_invalid_extended_length_in_second_block() {
    let mut s = "CT0C11223344HM0155667788".to_owned();
    let to_append = "1CEDCAFFE1A77E".repeat(100);
    s += &to_append;
    let num_opt_blocks = 2;
    let result = OptBlock::new_from_str(&s, num_opt_blocks);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: Invalid length field: value 1 is too small (must be at least 4)"
    );
}

#[test]
fn test_export_str() {
    // Single block
    let mut block1 = OptBlock::new_empty();
    block1.set_id("CT").unwrap();
    block1.set_data("1CEDCAFFE1A77E").unwrap();
    assert_eq!(block1.export_str().unwrap(), "CT121CEDCAFFE1A77E");

    // Multiple blocks
    let mut block2 = OptBlock::new_empty();
    block2.set_id("CT").unwrap();
    let data = "1CEDCAFFE1A77E".repeat(100);
    block2.set_data(&data).unwrap();
    let mut expected = String::new();
    expected.push_str("CT");
    write!(&mut expected, "0002{:04X}", data.len() + 10).unwrap();
    expected.push_str(&data);
    assert_eq!(block2.export_str().unwrap(), expected);
}

#[test]
fn test_export_str_invalid_length() {
    let opt_block = OptBlock::new_empty();
    let result = opt_block.export_str();
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: Length must be greater than 4, indicating uninitialized OptBlock"
    );
}

#[test]
fn test_set_id() {
    let mut opt_block = OptBlock::new_empty();
    opt_block.set_id("CT").unwrap();
    assert_eq!(opt_block.id(), "CT");

    let result = opt_block.set_id("XX");
    assert!(result.is_err());
}

#[test]
fn test_set_data_invalid_id_not_set() {
    let mut opt_block = OptBlock::new_empty();
    let result = opt_block.set_data("test");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "ERROR TR-31 OPT BLOCK: ID not set (has to be set before data)"
    );
}

#[test]
fn test_append() {
    let mut block1 = OptBlock::new("CT", "11", None).unwrap();
    let block2 = OptBlock::new("IK", "22", None).unwrap();
    let block3 = OptBlock::new("PB", "FF", None).unwrap();

    block1.append(block2);
    block1.append(block3);

    assert_eq!(block1.export_str().unwrap(), "CT0611IK0622PB06FF");
}
