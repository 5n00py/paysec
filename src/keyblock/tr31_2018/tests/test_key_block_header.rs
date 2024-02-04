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
