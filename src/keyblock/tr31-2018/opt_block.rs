use std::fmt::Write;

/// Represents an optional block as defined in the TR-31 specification.
///
/// An optional block is a block of data that is used to hold optional data within a TR-31 key block.
/// It is identified by a two ascii char identifier (`id`), followed by a two ascii hex length field or
/// a six ascii hex extended length field in case length > 255, and a variable-length data field (`data`)
/// consisting of ascii printable characters.
///
/// The `next` field is an optional pointer to the next `OptBlock` in the chain,
/// allowing for the creation of a linked list of optional blocks.
///
/// # References
///
/// - TR-31: 2018, p. 17-18, 27-33.
#[derive(Debug, PartialEq, Clone)]
pub struct OptBlock {
    /// Identifier of the optional block. Must be two ASCII characters.
    id: String,

    /// The data contained within the block. Consists of ASCII printable characters.
    data: String,

    /// The length of the `data` field in bytes.
    length: usize,

    /// Optional pointer to the next `OptBlock` in the sequence.
    next: Option<Box<OptBlock>>,
}
