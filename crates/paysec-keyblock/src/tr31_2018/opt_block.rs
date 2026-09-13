//! Module for TR-31 Optional Blocks.
//!
//! This module defines the [`OptBlock`] type representing an optional block
//! within a TR-31 key block.
//!
//! Optional blocks contain supplementary information associated with a key
//! block and can be linked together to form a sequence.
//!
//! # Format
//!
//! An optional block consists of:
//!
//! - a two-character identifier,
//! - a length field,
//! - ASCII data,
//! - optionally, another optional block.
//!
//! Blocks shorter than 256 bytes use the normal two-character hexadecimal
//! length field. Larger blocks use the TR-31 extended-length representation.
//!
//! # Example
//!
//! ```
//! use paysec_keyblock::OptBlock;
//!
//! let opt_block =
//!     OptBlock::new("CT", "ExampleData", None).unwrap();
//!
//! assert_eq!(opt_block.id(), "CT");
//! assert_eq!(opt_block.data(), "ExampleData");
//!
//! let next_block =
//!     OptBlock::new("PB", "PaddingData", None).unwrap();
//!
//! let mut chain = opt_block;
//! chain.append(next_block);
//!
//! let exported = chain.export_str().unwrap();
//!
//! assert!(!exported.is_empty());
//! ```
//!
//! # References
//!
//! TR-31: 2018, p. 17-18, 27-33.

use super::error::OptBlockError;
use super::header_constants::ALLOWED_OPT_BLOCK_IDS;

/// Represent an optional block as defined by TR-31.
///
/// Each block contains:
///
/// - a two-character identifier,
/// - ASCII data,
/// - the encoded total block length,
/// - an optional link to another block.
#[derive(Debug, PartialEq, Clone)]
pub struct OptBlock {
    id: String,
    data: String,
    length: usize,
    next: Option<Box<OptBlock>>,
}

impl OptBlock {
    /// Create a new optional block.
    ///
    /// # Parameters
    ///
    /// * `id` - TR-31 optional-block identifier.
    /// * `data` - ASCII optional-block data.
    /// * `next` - Optional next block in the chain.
    ///
    /// # Errors
    ///
    /// Returns [`OptBlockError::InvalidId`] if the identifier is unsupported.
    ///
    /// Returns [`OptBlockError::NonAsciiData`] if the data contains non-ASCII
    /// characters.
    ///
    /// Returns [`OptBlockError::BlockTooLong`] if the encoded block exceeds
    /// 65535 bytes.
    pub fn new(id: &str, data: &str, next: Option<OptBlock>) -> Result<Self, OptBlockError> {
        let mut opt_block = Self::new_empty();

        opt_block.set_id(id)?;
        opt_block.set_data(data)?;
        opt_block.set_next(next);

        Ok(opt_block)
    }

    /// Create an empty optional block.
    pub fn new_empty() -> Self {
        Self {
            id: String::new(),
            data: String::new(),
            length: 0,
            next: None,
        }
    }

    /// Parse one or more linked optional blocks from their string
    /// representation.
    ///
    /// # Parameters
    ///
    /// * `s` - Encoded optional-block data.
    /// * `num_opt_blocks` - Number of linked optional blocks expected.
    ///
    /// # Errors
    ///
    /// Returns an [`OptBlockError`] if the input is malformed, truncated,
    /// contains invalid length information, uses an unsupported identifier,
    /// or contains non-ASCII data.
    pub fn new_from_str(s: &str, num_opt_blocks: usize) -> Result<Self, OptBlockError> {
        if !s.is_ascii() {
            return Err(OptBlockError::NonAsciiInput);
        }

        if s.len() < 4 {
            return Err(OptBlockError::StringTooShort {
                minimum: 4,
                actual: s.len(),
            });
        }

        let mut opt_block = Self::new_empty();

        opt_block.set_id(&s[..2])?;

        let data_start_offset;

        if &s[2..4] == "00" {
            // Extended-length blocks necessarily have a total encoded length
            // greater than 255 bytes.
            if s.len() < 256 {
                return Err(OptBlockError::ExtendedLengthStringTooShort {
                    minimum: 256,
                    actual: s.len(),
                });
            }

            let ext_block_len = &s[4..10];

            opt_block.length = Self::ext_len_from_str(ext_block_len)?;

            data_start_offset = 10;
        } else {
            opt_block.length = Self::len_from_str(&s[2..4])?;

            data_start_offset = 4;
        }

        if s.len() < opt_block.length {
            return Err(OptBlockError::StringTooShortForLength {
                required: opt_block.length,
                actual: s.len(),
            });
        }

        opt_block.set_data(&s[data_start_offset..opt_block.length])?;

        if num_opt_blocks > 1 {
            let next_block_str = &s[opt_block.length..];

            let next_block = Self::new_from_str(next_block_str, num_opt_blocks - 1)?;

            opt_block.set_next(Some(next_block));
        }

        Ok(opt_block)
    }

    /// Serialize this optional block and all following linked blocks.
    ///
    /// # Errors
    ///
    /// Returns [`OptBlockError::Uninitialized`] if this block does not contain
    /// a valid initialized length.
    ///
    /// Errors from subsequent linked blocks are propagated unchanged.
    pub fn export_str(&self) -> Result<String, OptBlockError> {
        if self.length < 4 {
            return Err(OptBlockError::Uninitialized {
                length: self.length,
            });
        }

        let mut result = String::new();

        result.push_str(&self.id);

        if self.length < 256 {
            result.push_str(&format!("{:02X}", self.length,));
        } else {
            result.push_str(&format!("0002{:04X}", self.length,));
        }

        result.push_str(&self.data);

        if let Some(next) = &self.next {
            result.push_str(&next.export_str()?);
        }

        Ok(result)
    }

    /// Set the optional-block identifier.
    ///
    /// # Errors
    ///
    /// Returns [`OptBlockError::InvalidId`] if `id` is not a supported TR-31
    /// optional-block identifier.
    pub fn set_id(&mut self, id: &str) -> Result<(), OptBlockError> {
        if Self::is_allowed_id(id) {
            self.id = id.to_string();

            Ok(())
        } else {
            Err(OptBlockError::InvalidId(id.to_string()))
        }
    }

    /// Return the optional-block identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Set the optional-block data and recalculate the encoded block length.
    ///
    /// # Errors
    ///
    /// Returns [`OptBlockError::IdNotSet`] if the identifier has not first
    /// been configured.
    ///
    /// Returns [`OptBlockError::NonAsciiData`] if `data` contains non-ASCII
    /// characters.
    ///
    /// Returns [`OptBlockError::BlockTooLong`] if the resulting encoded block
    /// exceeds 65535 bytes.
    pub fn set_data(&mut self, data: &str) -> Result<(), OptBlockError> {
        if self.id.len() != 2 {
            return Err(OptBlockError::IdNotSet);
        }

        if !data.is_ascii() {
            return Err(OptBlockError::NonAsciiData(data.to_string()));
        }

        self.data = data.to_string();

        self.set_length()?;

        Ok(())
    }

    /// Return the optional-block data.
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Calculate and store this block's encoded length.
    ///
    /// Blocks shorter than 256 bytes use the normal two-character length
    /// field. Larger blocks require the six additional characters used by the
    /// extended-length representation.
    fn set_length(&mut self) -> Result<(), OptBlockError> {
        const MAX_OPT_BLOCK_LENGTH: usize = 65535;

        let minimum_length = self.id.len() + 2 + self.data.len();

        self.length = if minimum_length < 256 {
            minimum_length
        } else {
            minimum_length + 6
        };

        if self.length > MAX_OPT_BLOCK_LENGTH {
            let actual = self.length;

            self.length = 0;

            return Err(OptBlockError::BlockTooLong {
                maximum: MAX_OPT_BLOCK_LENGTH,
                actual,
            });
        }

        Ok(())
    }

    /// Return this optional block's encoded length.
    pub fn length(&self) -> &usize {
        &self.length
    }

    /// Set the next optional block.
    pub fn set_next(&mut self, next_block: Option<OptBlock>) {
        self.next = next_block.map(Box::new);
    }

    /// Return the next optional block, if one exists.
    pub fn next(&self) -> Option<&OptBlock> {
        self.next.as_deref()
    }

    /// Append an optional block to the end of this block chain.
    pub fn append(&mut self, opt_block_to_append: OptBlock) {
        match &mut self.next {
            Some(next_block) => {
                next_block.append(opt_block_to_append);
            }

            None => {
                self.set_next(Some(opt_block_to_append));
            }
        }
    }

    /// Return whether an optional-block identifier is supported.
    pub fn is_allowed_id(id: &str) -> bool {
        ALLOWED_OPT_BLOCK_IDS.contains(&id)
    }

    /// Return the total encoded length of this block and all linked blocks.
    pub fn total_length(&self) -> usize {
        let mut total = self.length;

        if let Some(next) = &self.next {
            total += next.total_length();
        }

        total
    }

    /// Parse a normal two-character hexadecimal optional-block length.
    fn len_from_str(s: &str) -> Result<usize, OptBlockError> {
        if s.len() != 2 {
            return Err(OptBlockError::InvalidLengthFieldWidth {
                value: s.to_string(),
                expected: 2,
            });
        }

        let length = usize::from_str_radix(s, 16).map_err(|source| {
            OptBlockError::InvalidLengthFieldHex {
                value: s.to_string(),
                source,
            }
        })?;

        if length < 4 {
            return Err(OptBlockError::LengthFieldTooSmall {
                minimum: 4,
                actual: length,
            });
        }

        Ok(length)
    }

    /// Parse the six-character extended optional-block length field.
    fn ext_len_from_str(s: &str) -> Result<usize, OptBlockError> {
        if s.len() != 6 {
            return Err(OptBlockError::InvalidExtendedLengthField(s.to_string()));
        }

        let length_of_length = &s[0..2];

        if length_of_length != "02" {
            return Err(OptBlockError::InvalidLengthOfLengthField(
                length_of_length.to_string(),
            ));
        }

        let encoded_length = &s[2..6];

        let length = usize::from_str_radix(encoded_length, 16).map_err(|source| {
            OptBlockError::InvalidExtendedLengthHex {
                value: encoded_length.to_string(),
                source,
            }
        })?;

        if length <= 255 {
            return Err(OptBlockError::ExtendedLengthTooSmall {
                value: encoded_length.to_string(),
            });
        }

        Ok(length)
    }
}
