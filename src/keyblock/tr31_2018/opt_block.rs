//! Module for TR-31 Optional Blocks.
//!
//! This module defines the `OptBlock` struct which represents an optional block
//! in a TR-31 key block. In TR-31, optional blocks are used to store additional,
//! non-standard data within a key block. These blocks are identified by unique
//! identifiers and can be linked together to form a chain of optional data segments.
//!
//! # Format
//!
//! An optional block consists of:
//! - An identifier (`id`): A two-character ASCII string identifying the type of data.
//! - A length field: Indicating the length of the optional block and varies depending on the size of the block:
//!   - A two-byte hex-ASCII value of the length is below 256 bytes
//!   - An extended length field for largers sized blocks
//! - A data field (`data`): A variable-length string of ASCII printable characters.
//!
//! # Usage
//!
//! Optional blocks are used in various contexts within a TR-31 key block, such as for
//! additional metadata, custom fields, or other supplementary information that does not
//! fit into the standard key block structure.
//!
//! # References
//!
//! TR-31: 2018, p. 17-18, 27-33.

use std::error::Error;
use std::fmt::Write;

/// Represent an optional block as defined in the TR-31 specification.
///
/// Each `OptBlock` is identified by a two-character ASCII `id`, followed by a length field
/// indicating the size of the data, and the `data` itself which consists of ASCII printable characters.
/// The `length` field is a `usize` and represents the byte size of the `data` field.
/// The `next` field allows for the chaining of multiple `OptBlock`s to store a sequence of data.
///
/// # Fields
///
/// - `id`: A two-character ASCII string identifier for the optional block.
/// - `data`: A string containing the data of the block, composed of ASCII printable characters.
/// - `length`: The size of the `data` field in bytes, represented as a `usize`.
/// - `next`: An optional pointer to the next `OptBlock` in the chain.
#[derive(Debug, PartialEq, Clone)]
pub struct OptBlock {
    id: String,
    data: String,
    length: usize,
    next: Option<Box<OptBlock>>,
}

impl OptBlock {
    /// Allowed IDs for an optional block, cf. TR-31: 2018, p. 28-29.
    const ALLOWED_IDS: [&'static str; 9] = ["CT", "HM", "IK", "KC", "KP", "KS", "KV", "PB", "TS"];

    /// Create a new `OptBlock` instance with the specified `id`, `data`, and optional `next` block.
    ///
    /// # Arguments
    ///
    /// * `id` - The identifier for the new block, which must be one of the valid values defined in `ALLOWED_IDS`.
    /// * `data` - The data associated with the block, which must consist entirely of ASCII characters.
    /// * `next` - An optional `OptBlock` instance representing the next block in a linked list of blocks.
    ///
    /// # Returns
    ///
    /// A `Result` containing either an `OptBlock` instance or a boxed error.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    /// - If the specified `id` is not one of the valid values defined in `ALLOWED_IDS`.
    /// - If the specified `data` contains non-ASCII characters.
    /// - If the total length of the `OptBlock` instance exceeds 65535 characters.
    pub fn new(id: &str, data: &str, next: Option<OptBlock>) -> Result<Self, Box<dyn Error>> {
        let mut opt_block = Self::new_empty();
        opt_block.set_id(id)?;
        opt_block.set_data(data)?;
        opt_block.set_next(next);
        Ok(opt_block)
    }

    /// Create a new empty `OptBlock`.
    ///
    /// This function creates a new `OptBlock` instance with empty `id`, `data`, and `next`
    /// fields and `length` set to zero.
    pub fn new_empty() -> Self {
        Self {
            id: String::new(),
            data: String::new(),
            length: 0,
            next: None,
        }
    }

    /// Construct a new `OptBlock` instance by parsing an input string.
    ///
    /// # Arguments
    ///
    /// * `s` - The input string to parse.
    /// * `num_opt_blocks` - The expected number of opt blocks to parse.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the parsed `OptBlock` instance or a boxed error.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    /// - If the input string is too short or does not meet the expected format.
    /// - If the length field is invalid or the string is too short for the given length.
    /// - If `set_id` or `set_data` fails.
    /// - If there are any errors while constructing the linked list of `OptBlock` instances.
    pub fn new_from_str(s: &str, num_opt_blocks: usize) -> Result<Self, Box<dyn Error>> {
        if s.len() < 4 {
            return Err(
                "ERROR TR-31 OPT BLOCK: String too short. Expected at least 4 characters".into(),
            );
        }

        let mut opt_block = Self::new_empty();
        opt_block.set_id(&s[..2])?;

        let data_start_offset: usize;
        if &s[2..4] == "00" {
            if s.len() < 256 {
                return Err("ERROR TR-31 OPT BLOCK: String containing extended length too short. Expected at least 256 characters".into());
            }
            let ext_block_len = &s[4..10];
            opt_block.length = Self::ext_len_from_str(ext_block_len)?;
            data_start_offset = 10;
        } else {
            opt_block.length = Self::len_from_str(&s[2..4])?;
            data_start_offset = 4;
        }

        if s.len() < opt_block.length {
            return Err(format!(
                "ERROR TR-31 OPT BLOCK: String too short for given length. Expected at least {} characters.",
                opt_block.length
            ).into());
        }

        opt_block.set_data(&s[data_start_offset..opt_block.length])?;

        // Parsing the next block if more than one block is expected
        if num_opt_blocks > 1 {
            // Recursively parse the next block
            let next_block_str = &s[opt_block.length..];
            let next_block = OptBlock::new_from_str(next_block_str, num_opt_blocks - 1)?;

            // Set the next block
            opt_block.set_next(Some(next_block));
        }

        Ok(opt_block)
    }

    /// Return a string representation of the `OptBlock` and its contents.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the string representation of the `OptBlock` or a boxed error.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    /// - If the length of the `OptBlock` is less than 4, indicating an uninitialized `OptBlock`.
    /// - If there are any errors while formatting the length field.
    pub fn export_str(&self) -> Result<String, Box<dyn Error>> {
        if self.length < 4 {
            return Err("ERROR TR-31 OPT BLOCK: Length must be greater than 4, indicating uninitialized OptBlock".into());
        }

        let mut res = String::new();

        // Optional Block ID
        res.push_str(&self.id);

        // Optional Block Length
        if self.length < 256 {
            write!(&mut res, "{:02X}", self.length)?;
        } else {
            write!(&mut res, "0002{:04X}", self.length)?;
        }

        // Optional Block Data
        res.push_str(&self.data);

        // Additional Optional Blocks, if present
        if let Some(next) = &self.next {
            res.push_str(&next.export_str()?);
        }

        Ok(res)
    }

    /// Set the identifier for this `OptBlock` instance.
    ///
    /// # Arguments
    ///
    /// * `id` - The identifier to set for this `OptBlock` instance.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success (`Ok`) or containing a boxed error (`Err`) if an error occurs.
    ///
    /// # Errors
    ///
    /// This function returns an error if the input identifier is not valid. The identifier must be
    /// included in the list of allowed identifiers.
    pub fn set_id(&mut self, id: &str) -> Result<(), Box<dyn Error>> {
        if Self::is_allowed_id(id) {
            self.id = id.to_string();
            Ok(())
        } else {
            Err(format!("ERROR TR-31 OPT BLOCK: Invalid ID: {}", id).into())
        }
    }

    /// Return the ID of the `OptBlock`
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Set the data field of the `OptBlock` instance to the given value and update the length of
    /// the block.
    ///
    /// # Arguments
    ///
    /// * `data` - The value to set as the data field.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success (`Ok`) or containing a boxed error (`Err`) if an error occurs.
    ///
    /// # Errors
    ///
    /// This function returns an error in the following cases:
    /// - If the ID has not been set before calling this function. The ID must be a two-character
    ///   ASCII string and must be set prior to setting the data.
    /// - If the input `data` string contains non-ASCII characters. The data field must consist only
    ///   of ASCII printable characters.
    pub fn set_data(&mut self, data: &str) -> Result<(), Box<dyn Error>> {
        if self.id.len() != 2 {
            return Err("ERROR TR-31 OPT BLOCK: ID not set (has to be set before data)".into());
        }
        if !data.chars().all(|c| c.is_ascii()) {
            return Err(format!(
                "ERROR TR-31 OPT BLOCK: Data has non ASCII characters: {}",
                data
            )
            .into());
        }
        self.data = data.to_string();
        self.set_length()?;
        Ok(())
    }

    /// Returns the data of the `OptBlock`
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Set the length of the current `OptBlock` instance based on the length of its ID and data
    /// fields. If the total length of the block exceeds 255 characters, an additional extended
    /// length field is added. If the total length exceeds 65535 characters, an error is
    /// returned. The length is stored in the `length` field of the `OptBlock` instance.
    ///
    /// # Returns
    ///
    /// A `Result` containing either `Ok(())` if the length is successfully set, or a boxed error.
    ///
    /// # Errors
    ///
    /// This function returns an error in the form of a `Box<dyn Error>` if the total length of the
    /// `OptBlock` instance exceeds 65535 characters.
    fn set_length(&mut self) -> Result<(), Box<dyn Error>> {
        // Minimum length containing ID length, length field length and data length
        let min_len: usize = self.id.len() + 2 + self.data.len();
        if min_len < 256 {
            self.length = min_len;
        } else {
            // If length of the optional header exceeds 255, additional extended length field of
            // length 6 is needed.
            self.length = min_len + 6;
        }
        if self.length > 65535 {
            let old_length = self.length;
            self.length = 0;
            return Err(format!(
                "ERROR TR-31 OPT BLOCK: Block size '{}' is too long (must be max. 65535)",
                old_length
            )
            .into());
        }
        Ok(())
    }

    /// Returns a reference to the length of the `OptBlock` instance.
    pub fn length(&self) -> &usize {
        &self.length
    }

    /// Set the next optional block.
    ///
    /// # Arguments
    ///
    /// * `next_block` - An optional `OptBlock` to be set as the next block.
    pub fn set_next(&mut self, next_block: Option<OptBlock>) {
        self.next = next_block.map(Box::new);
    }

    /// Return a reference to the next `OptBlock` instance in the linked list or `None` if there is
    /// no next `OptBlock`.
    pub fn next(&self) -> Option<&OptBlock> {
        self.next.as_deref()
    }

    /// Append an `OptBlock` to the end of the linked list of optional blocks.
    ///
    /// This method takes an `OptBlock` and appends it to the end of the current chain of `OptBlock`s.
    /// If the current `OptBlock` already has a next block linked, the method recursively traverses
    /// the chain until it finds the last block, to which the new block is then appended.
    ///
    /// # Arguments
    ///
    /// * `opt_block_to_append` - The `OptBlock` to be appended to the end of the current chain.
    pub fn append(&mut self, opt_block_to_append: OptBlock) {
        match &mut self.next {
            Some(ref mut next_block) => next_block.append(opt_block_to_append),
            None => self.set_next(Some(opt_block_to_append)),
        }
    }

    // pub fn finalize_with_pad_block(
    //     &mut self,
    //     pad_char: char,
    //     enc_block_size: usize,
    // ) -> Result<(), String> {
    //     // Check that enc_block_size is a multiple of 8 or 16
    //     if enc_block_size % 8 != 0 && enc_block_size % 16 != 0 {
    //         return Err(String::from(
    //             "ERROR TR-31 OPT BLOCK: Encryption block size must be a multiple of 8 or 16",
    //         ));
    //     }
    //
    //     // Check that pad_char is an ascii printable character
    //     if !pad_char.is_ascii() {
    //         return Err(String::from(
    //             "ERROR TR-31 OPT BLOCK: Padding character must be an ascii printable character",
    //         ));
    //     }
    //
    //     let total_length = self.total_length();
    //
    //     // If the length of all opt blocks is already a multiple of enc_block_size, no padding block needed.
    //     if total_length % enc_block_size == 0 {
    //         return Ok(());
    //     }
    //
    //     // Compute the padding length of the data to be padded, note that ID and length field already
    //     // take 4 bytes.
    //     let padding_length = enc_block_size - ((total_length + 4) % enc_block_size);
    //
    //     // Create the padding block
    //     let pad_data = pad_char.to_string().repeat(padding_length);
    //     let mut pad_block = OptBlock::new("PB", &pad_data, None)?;
    //
    //     // Append the padding block to the linked list
    //     self.append(pad_block);
    //
    //     Ok(())
    // }

    /// Determines whether the given `id` string is allowed.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID string to check.
    ///
    /// # Returns
    ///
    /// `true` if the ID is allowed, `false` otherwise.
    ///
    pub fn is_allowed_id(id: &str) -> bool {
        Self::ALLOWED_IDS.contains(&id)
    }

    /// Returns the total length of the `OptBlock`, including its own length and the lengths of all
    /// subsequent `OptBlock`s in the linked list.
    ///
    /// # Returns
    ///
    /// The total length of the `OptBlock` as a `usize` value..
    ///
    pub fn total_length(&self) -> usize {
        let mut total = self.length;
        if let Some(next) = &self.next {
            total += next.total_length();
        }
        total
    }

    /// Parse the length of an `OptBlock` from a hexadecimal-encoded string.
    ///
    /// # Arguments
    ///
    /// * `s` - A hexadecimal-encoded string representing the length of the `OptBlock`.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the length of the `OptBlock` as a `usize` value or a boxed error.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    /// - If the length string is not exactly 2 characters long.
    /// - If the string cannot be parsed as a hexadecimal number.
    /// - If the resulting length is less than 4.
    /// Errors are returned as a `Box<dyn Error>`, which can encompass various error types.
    fn len_from_str(s: &str) -> Result<usize, Box<dyn Error>> {
        if s.len() != 2 {
            return Err(Box::<dyn Error>::from(format!(
            "ERROR TR-31 OPT BLOCK: Invalid length field: Expected a string with 2 characters, found '{}'",
            s
        )));
        }

        let len = usize::from_str_radix(s, 16).map_err(|_| { 
            Box::<dyn Error>::from(format!("ERROR TR-31 OPT BLOCK: Invalid length field: '{}' is not a valid hexadecimal number", s)) 
        })?;

        if len < 4 {
            return Err(Box::<dyn Error>::from(format!(
            "ERROR TR-31 OPT BLOCK: Invalid length field: value {} is too small (must be at least 4)",
            len
        )));
        }

        Ok(len)
    }

    /// Convert the extended length field of a TR-31 message from a hexadecimal string to a `usize`.
    ///
    /// # Arguments
    ///
    /// * `s` - The input string to parse.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the parsed extended length as a `usize` or a boxed error.
    ///
    /// # Errors
    ///
    /// This function returns an error in the following cases:
    /// - If the input string does not have a length of 6 characters.
    /// - If the first two characters are not `02`.
    /// - If the resulting `usize` is less than or equal to 255.
    fn ext_len_from_str(s: &str) -> Result<usize, String> {
        if s.len() != 6 {
            return Err(format!(
                "ERROR TR-31 OPT BLOCK: Invalid extended length field: {}",
                s
            ));
        }
        if &s[0..2] != "02" {
            return Err(format!(
                "ERROR TR-31 OPT BLOCK: Invalid length of length field: {}",
                &s[0..2]
            ));
        }
        let res = usize::from_str_radix(&s[2..6], 16).map_err(|e| e.to_string())?;
        if res <= 255 {
            return Err(format!(
                "ERROR TR-31 OPT BLOCK: Extended length is not greater than 255: {}",
                &s[2..6]
            ));
        }
        Ok(res)
    }
}
