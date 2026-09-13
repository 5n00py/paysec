//! Module for TR-31 Key Block Headers.
//!
//! A TR-31 key block header contains the attributes associated with a
//! protected key, including its key block version, usage, algorithm, mode of
//! use, exportability, and optional blocks.
//!
//! The fixed portion of the header is 16 ASCII characters. Optional blocks,
//! when present, immediately follow the fixed header.

use super::error::KeyBlockHeaderError;
use super::header_constants::{
    ALLOWED_ALGORITHMS, ALLOWED_EXPORTABILITIES, ALLOWED_KEY_USAGES, ALLOWED_MODES_OF_USE,
    ALLOWED_VERSION_IDS,
};
use super::opt_block::OptBlock;

/// Represents a TR-31 key block header.
#[derive(Debug, PartialEq)]
pub struct KeyBlockHeader {
    version_id: String,
    kb_length: u16,
    key_usage: String,
    algorithm: String,
    mode_of_use: String,
    key_version_number: String,
    exportability: String,
    num_opt_blocks: u8,
    reserved_field: String,
    opt_blocks: Option<Box<OptBlock>>,
}

impl KeyBlockHeader {
    /// Create a new empty key block header.
    pub fn new_empty() -> Self {
        Self {
            version_id: String::new(),
            kb_length: 0,
            key_usage: String::new(),
            algorithm: String::new(),
            mode_of_use: String::new(),
            key_version_number: String::new(),
            exportability: String::new(),
            num_opt_blocks: 0,
            reserved_field: "00".to_string(),
            opt_blocks: None,
        }
    }

    /// Create a new key block header from individual header values.
    pub fn new_with_values(
        version_id: &str,
        key_usage: &str,
        algorithm: &str,
        mode_of_use: &str,
        key_version_number: &str,
        exportability: &str,
    ) -> Result<Self, KeyBlockHeaderError> {
        let mut header = Self::new_empty();

        header.set_version_id(version_id)?;

        header.set_key_usage(key_usage)?;

        header.set_algorithm(algorithm)?;

        header.set_mode_of_use(mode_of_use)?;

        header.set_key_version_number(key_version_number)?;

        header.set_exportability(exportability)?;

        Ok(header)
    }

    /// Parse a key block header from its string representation.
    ///
    /// The input may contain additional key block data after the header.
    /// Optional blocks are parsed according to the number declared in the
    /// fixed header.
    pub fn new_from_str(header_str: &str) -> Result<Self, KeyBlockHeaderError> {
        const FIXED_HEADER_LENGTH: usize = 16;

        if !header_str.is_ascii() {
            return Err(KeyBlockHeaderError::NonAsciiHeader);
        }

        if header_str.len() < FIXED_HEADER_LENGTH {
            return Err(KeyBlockHeaderError::InvalidDataLength {
                minimum: FIXED_HEADER_LENGTH,
                actual: header_str.len(),
            });
        }

        let version_id = header_str[0..1].to_string();

        let kb_length = header_str[1..5]
            .parse::<u16>()
            .map_err(|_| KeyBlockHeaderError::InvalidKeyBlockLength)?;

        let key_usage = header_str[5..7].to_string();

        let algorithm = header_str[7..8].to_string();

        let mode_of_use = header_str[8..9].to_string();

        let key_version_number = header_str[9..11].to_string();

        let exportability = header_str[11..12].to_string();

        let num_optional_blocks = header_str[12..14]
            .parse::<u8>()
            .map_err(|_| KeyBlockHeaderError::InvalidNumberOfOptionalBlocks)?;

        let reserved_field = header_str[14..16].to_string();

        let mut header = Self::new_empty();

        header.set_version_id(&version_id)?;

        header.set_kb_length(kb_length)?;

        header.set_key_usage(&key_usage)?;

        header.set_algorithm(&algorithm)?;

        header.set_mode_of_use(&mode_of_use)?;

        header.set_key_version_number(&key_version_number)?;

        header.set_exportability(&exportability)?;

        header.set_num_optional_blocks(num_optional_blocks)?;

        header.set_reserved_field(&reserved_field)?;

        if num_optional_blocks > 0 && header_str.len() < 20 {
            return Err(KeyBlockHeaderError::InvalidHeaderLengthWithOptionalBlocks {
                minimum: 20,
                actual: header_str.len(),
            });
        }

        if num_optional_blocks > 0 {
            let opt_block_str = &header_str[16..];

            let opt_block = OptBlock::new_from_str(opt_block_str, num_optional_blocks as usize)
                .map_err(KeyBlockHeaderError::FailedToParseOptionalBlocks)?;

            header.opt_blocks = Some(Box::new(opt_block));
        }

        Ok(header)
    }

    /// Export the key block header to its ASCII representation.
    pub fn export_str(&self) -> Result<String, KeyBlockHeaderError> {
        if self.version_id.is_empty()
            || self.key_usage.is_empty()
            || self.algorithm.is_empty()
            || self.mode_of_use.is_empty()
            || self.key_version_number.is_empty()
            || self.exportability.is_empty()
            || self.reserved_field.is_empty()
        {
            return Err(KeyBlockHeaderError::ExportFailedEmptyFields);
        }

        let mut header_str = String::new();

        header_str.push_str(self.version_id());

        header_str.push_str(&format!("{:04}", self.kb_length(),));

        header_str.push_str(self.key_usage());

        header_str.push_str(self.algorithm());

        header_str.push_str(self.mode_of_use());

        header_str.push_str(self.key_version_number());

        header_str.push_str(self.exportability());

        header_str.push_str(&format!("{:02}", self.num_opt_blocks,));

        header_str.push_str(self.reserved_field());

        if let Some(opt_blocks) = &self.opt_blocks {
            header_str.push_str(&opt_blocks.export_str()?);
        }

        Ok(header_str)
    }

    /// Set the key block version identifier.
    pub fn set_version_id(&mut self, value: &str) -> Result<(), KeyBlockHeaderError> {
        if ALLOWED_VERSION_IDS.contains(&value) {
            self.version_id = value.to_string();

            Ok(())
        } else {
            Err(KeyBlockHeaderError::InvalidVersionId(value.to_string()))
        }
    }

    /// Return the key block version identifier.
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    /// Set the complete key block length.
    pub fn set_kb_length(&mut self, value: u16) -> Result<(), KeyBlockHeaderError> {
        if value > 9999 {
            return Err(KeyBlockHeaderError::InvalidKeyBlockLength);
        }

        self.kb_length = value;

        Ok(())
    }

    /// Return the complete key block length.
    pub fn kb_length(&self) -> u16 {
        self.kb_length
    }

    /// Set the key usage.
    pub fn set_key_usage(&mut self, value: &str) -> Result<(), KeyBlockHeaderError> {
        if ALLOWED_KEY_USAGES.contains(&value) {
            self.key_usage = value.to_string();

            Ok(())
        } else {
            Err(KeyBlockHeaderError::InvalidKeyUsage(value.to_string()))
        }
    }

    /// Return the key usage.
    pub fn key_usage(&self) -> &str {
        &self.key_usage
    }

    /// Set the protected-key algorithm.
    pub fn set_algorithm(&mut self, value: &str) -> Result<(), KeyBlockHeaderError> {
        if ALLOWED_ALGORITHMS.contains(&value) {
            self.algorithm = value.to_string();

            Ok(())
        } else {
            Err(KeyBlockHeaderError::InvalidAlgorithm(value.to_string()))
        }
    }

    /// Return the protected-key algorithm.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Set the key mode of use.
    pub fn set_mode_of_use(&mut self, value: &str) -> Result<(), KeyBlockHeaderError> {
        if ALLOWED_MODES_OF_USE.contains(&value) {
            self.mode_of_use = value.to_string();

            Ok(())
        } else {
            Err(KeyBlockHeaderError::InvalidModeOfUse(value.to_string()))
        }
    }

    /// Return the key mode of use.
    pub fn mode_of_use(&self) -> &str {
        &self.mode_of_use
    }

    /// Set the key version number.
    pub fn set_key_version_number(&mut self, value: &str) -> Result<(), KeyBlockHeaderError> {
        if value.len() != 2 {
            return Err(KeyBlockHeaderError::InvalidKeyVersionNumberLength(
                value.to_string(),
            ));
        }

        if !value.is_ascii() {
            return Err(KeyBlockHeaderError::InvalidKeyVersionNumberEncoding(
                value.to_string(),
            ));
        }

        self.key_version_number = value.to_string();

        Ok(())
    }

    /// Return the key version number.
    pub fn key_version_number(&self) -> &str {
        &self.key_version_number
    }

    /// Set the exportability attribute.
    pub fn set_exportability(&mut self, value: &str) -> Result<(), KeyBlockHeaderError> {
        if ALLOWED_EXPORTABILITIES.contains(&value) {
            self.exportability = value.to_string();

            Ok(())
        } else {
            Err(KeyBlockHeaderError::InvalidExportability(value.to_string()))
        }
    }

    /// Return the exportability attribute.
    pub fn exportability(&self) -> &str {
        &self.exportability
    }

    /// Set the number of optional blocks declared in the header.
    pub fn set_num_optional_blocks(&mut self, value: u8) -> Result<(), KeyBlockHeaderError> {
        const MAX_OPTIONAL_BLOCKS: u8 = 99;

        if value > MAX_OPTIONAL_BLOCKS {
            return Err(KeyBlockHeaderError::TooManyOptionalBlocks {
                maximum: MAX_OPTIONAL_BLOCKS,
                actual: value,
            });
        }

        self.num_opt_blocks = value;

        Ok(())
    }

    /// Return the number of optional blocks declared in the header.
    pub fn num_optional_blocks(&self) -> u8 {
        self.num_opt_blocks
    }

    /// Set the TR-31 reserved header field.
    pub fn set_reserved_field(&mut self, value: &str) -> Result<(), KeyBlockHeaderError> {
        if value == "00" {
            self.reserved_field = value.to_string();

            Ok(())
        } else {
            Err(KeyBlockHeaderError::InvalidReservedField(value.to_string()))
        }
    }

    /// Return the reserved header field.
    pub fn reserved_field(&self) -> &str {
        &self.reserved_field
    }

    /// Replace the linked optional blocks and update their count.
    pub fn set_opt_blocks(&mut self, opt_blocks: Option<Box<OptBlock>>) {
        self.opt_blocks = opt_blocks;

        self.num_opt_blocks = 0;

        if let Some(opt_block) = &self.opt_blocks {
            let mut current_block = opt_block.as_ref();

            self.num_opt_blocks = 1;

            while let Some(next_block) = current_block.next() {
                self.num_opt_blocks += 1;
                current_block = next_block;
            }
        }
    }

    /// Append one or more optional blocks to the existing optional-block
    /// chain.
    pub fn append_opt_blocks(&mut self, opt_block_to_append: OptBlock) {
        let mut additional_blocks_count = 1;

        let mut current_block = &opt_block_to_append;

        while let Some(next_block) = current_block.next() {
            additional_blocks_count += 1;

            current_block = next_block;
        }

        match &mut self.opt_blocks {
            Some(existing_opt_block) => {
                existing_opt_block.append(opt_block_to_append);
            }

            None => {
                self.opt_blocks = Some(Box::new(opt_block_to_append));
            }
        }

        self.num_opt_blocks += additional_blocks_count;
    }

    /// Return the optional-block chain.
    pub fn opt_blocks(&self) -> &Option<Box<OptBlock>> {
        &self.opt_blocks
    }

    /// Return the complete encoded header length, including optional blocks.
    pub fn len(&self) -> usize {
        let mut header_length = 16;

        if let Some(opt_blocks) = &self.opt_blocks {
            header_length += opt_blocks.total_length();
        }

        header_length
    }

    /// Finalize the header by padding optional blocks to the cipher block
    /// boundary when required.
    pub fn finalize(&mut self) -> Result<(), KeyBlockHeaderError> {
        let block_size = if self.version_id == "D" { 16 } else { 8 };

        let header_length = self.len();

        if let Some(opt_blocks) = &mut self.opt_blocks {
            if header_length % block_size != 0 {
                let mut padding_needed = block_size - (header_length % block_size);

                // A padding optional block must contain at least:
                //
                // - two-byte ID,
                // - two-byte length,
                // - two padding characters.
                if padding_needed < 6 {
                    padding_needed += block_size;
                }

                let padding_data_length = padding_needed - 4;

                let padding_data = "0".repeat(padding_data_length);

                let padding_block = OptBlock::new("PB", &padding_data, None)?;

                opt_blocks.append(padding_block);

                self.num_opt_blocks += 1;
            }
        }

        Ok(())
    }
}

#[test]
fn test_header_invalid_version_typed_error() {
    let result = KeyBlockHeader::new_with_values("X", "P0", "A", "E", "00", "E");

    assert!(matches!(
        result,
        Err(KeyBlockHeaderError::InvalidVersionId(_))
    ));
}

#[test]
fn test_header_optional_block_error_is_preserved() {
    use crate::OptBlockError;

    let result = KeyBlockHeader::new_from_str("D0020P0AE00E0100XX04");

    assert!(matches!(
        result,
        Err(KeyBlockHeaderError::FailedToParseOptionalBlocks(
            OptBlockError::InvalidId(_)
        ))
    ));
}
