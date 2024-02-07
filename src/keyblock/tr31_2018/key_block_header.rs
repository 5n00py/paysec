//! Module for TR-31 Key Block Headers.
//!
//! This module provides the `KeyBlockHeader` struct, essential for constructing and interpreting
//! TR-31 key blocks. A TR-31 key block is a standardized format for secure exchange and storage of
//! cryptographic keys. The header of a key block contains attribute information about the key,
//! using uppercase ASCII printable characters for better supportability and human readability. The
//! encoding and acceptable characters for each field are defined individually, as outlined in
//! TR-31 specification.
//!
//! # Key Features
//! - **Key Block Version ID**: Identifies the key block version, defining its cryptographic
//!   protection method and content layout. Different versions (A, B, C, D) have specific protection methods.
//! - **Key Block Length**: Specifies the total length of the key block in ASCII numeric digits, including
//!   the header, encrypted data, and MAC.
//! - **Key Usage**: Indicates the function of the protected key or sensitive data, with values defined in the standard.
//! - **Algorithm**: Details the approved algorithm for which the protected key may be used.
//! - **Mode of Use**: Defines permissible operations with the protected key.
//! - **Key Version Number**: Optional two-digit ASCII version number for key management purposes.
//! - **Exportability**: Indicates the transferability of the protected key outside its cryptographic domain.
//! - **Number of Optional Blocks**: Defines the number of included Optional Blocks in the key block.
//! - **Reserved Field**: Reserved for future use, currently filled with ASCII zero characters.
//! - **Optional Blocks**: Supports additional data segments for flexibility and extensibility.
//!
//! # Key Header Fields as defined in TR-31 Specification Page 15ff.
//! - **Byte 0**: Key Block Version ID (1AN, Encrypted: No)
//! - **Bytes 1-4**: Key Block Length (4N, Encrypted: No)
//! - **Bytes 5-6**: Key Usage (2AN, Encrypted: No)
//! - **Byte 7**: Algorithm (1AN, Encrypted: No)
//! - **Byte 8**: Mode of Use (1AN, Encrypted: No)
//! - **Bytes 9-10**: Key Version Number (2AN, Encrypted: No)
//! - **Byte 11**: Exportability (1AN, Encrypted: No)
//! - **Bytes 12-13**: Number of Optional Blocks (2N, Encrypted: No)
//! - **Bytes 14-15**: Reserved for Future Use (2N, Encrypted: No)
//! - **Bytes 16+**: First Optional Block ID (if present)
//!
//! # Usage
//! This module is used in systems where cryptographic key management is crucial, such as banking
//! and financial systems, secure communications, and others.
//!
//! # Example
//! ```
//! use paysec::keyblock::KeyBlockHeader;
//! use paysec::keyblock::OptBlock;
//!
//! // Example of creating a new KeyBlockHeader with an optional block
//! let mut header = KeyBlockHeader::new_with_values("D", "P0", "A", "E", "00", "E").unwrap();
//! let opt_block = OptBlock::new("CT", "SomeData", None).unwrap();
//! header.set_opt_blocks(Some(Box::new(opt_block)));
//!
//! // Finalize the header to ensure it conforms to block size requirements
//! header.finalize().unwrap();
//!
//! // Set the key block length to the length of the header, as for the example
//! let header_length = header.len();
//! header.set_kb_length(header_length as u16).unwrap();
//!
//! // Export the header as a string
//! let header_str = header.export_str().unwrap();
//!
//! // Example of how the header would look as a string
//! let expected_header_str = "D0048P0AE00E0200CT0CSomeDataPB140000000000000000";
//! assert_eq!(header_str, expected_header_str, "Header string representation mismatch");
//! ```
//!
//! # References
//! - TR-31: 2018, p. 15ff.

use super::opt_block::OptBlock;

use std::error::Error;

/// Represents the header of a TR-31 Key Block.
///
/// The `KeyBlockHeader` struct encapsulates all the necessary information
/// required to define the characteristics of a key block according to
/// TR-31 standards. It includes fields for version ID, key usage,
/// algorithm, mode of use, etc., and supports optional blocks for
/// additional data.
///
/// # Fields
/// - `version_id`: Identifies the version of the key block, determining its cryptographic
///                 protection method and the layout.
/// - `kb_length`: Specifies the total length of the key block after encoding,
///                including the header, encrypted data, and MAC.
/// - `key_usage`: Indicates the intended function of the protected key/sensitive data.
/// - `algorithm`: Specifies the algorithm to be used for the protected key.
/// - `mode_of_use`: Defines the operation that the protected key can perform.
/// - `key_version_number`: Optional version number of the key, used for key management.
/// - `exportability`: Indicates the exportability of the protected key.
/// - `num_opt_blocks`: Number of optional blocks included in the key block.
/// - `reserved_field`: Reserved for future use, currently filled with zero characters.
/// - `opt_blocks`: Contains additional optional blocks of data if present.
///
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
    /// Predefined allowed version IDs for the key block.
    const ALLOWED_VERSION_IDS: [&'static str; 4] = ["A", "B", "C", "D"];

    /// Predefined allowed key usages for the key block.
    const ALLOWED_KEY_USAGES: [&'static str; 29] = [
        "B0", "B1", "B2", "C0", "D0", "D1", "D2", "E0", "E1", "E2", "E3", "E4", "E5", "E6", "K0",
        "K1", "K2", "K3", "M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "P0", "S0",
    ];

    /// Predefined allowed algorithms for the key block.
    const ALLOWED_ALGORITHMS: [&'static str; 7] = ["A", "D", "E", "H", "R", "S", "T"];

    /// Predefined allowed modes of use for the key block.
    const ALLOWED_MODES_OF_USE: [&'static str; 11] =
        ["B", "C", "D", "E", "G", "N", "S", "T", "V", "X", "Y"];

    /// Predefined allowed exportabilities for the key block.
    const ALLOWED_EXPORTABILITIES: [&'static str; 3] = ["E", "N", "S"];

    /// Create a new, empty `KeyBlockHeader`.
    ///
    /// Initializes all string fields to empty strings, numerical fields to zero,
    /// and sets `opt_blocks` to `None`.
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

    /// Create a new `KeyBlockHeader` with provided values.
    ///
    /// Initializes the header with the specified values, applying validations
    /// for each field. Returns an error if any value is invalid.
    ///
    /// # Arguments
    ///
    /// * `version_id` - Version ID of the key block.
    /// * `key_usage` - Intended function of the protected key/sensitive data.
    /// * `algorithm` - Algorithm to be used for the protected key.
    /// * `mode_of_use` - Operation that the protected key can perform.
    /// * `key_version_number` - Optional version number of the key.
    /// * `exportability` - Exportability of the protected key.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` with the new `KeyBlockHeader`, or an `Err` with a boxed error.
    pub fn new_with_values(
        version_id: &str,
        key_usage: &str,
        algorithm: &str,
        mode_of_use: &str,
        key_version_number: &str,
        exportability: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let mut header = KeyBlockHeader::new_empty();
        header.set_version_id(version_id)?;
        header.set_key_usage(key_usage)?;
        header.set_algorithm(algorithm)?;
        header.set_mode_of_use(mode_of_use)?;
        header.set_key_version_number(key_version_number)?;
        header.set_exportability(exportability)?;

        Ok(header)
    }

    /// Parse a `KeyBlockHeader` from a string representation.
    ///
    /// This function extracts values for each field from the string and initializes the header.
    /// It validates the length of the string and each field value. Optionally, it parses
    /// and includes optional blocks if present.
    ///
    /// # Arguments
    ///
    /// * `header_str` - A string slice representing the key block header.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` with a new `KeyBlockHeader` if parsing is successful,
    /// or an `Err` containing a boxed error describing the issue.
    pub fn new_from_str(header_str: &str) -> Result<Self, Box<dyn Error>> {
        if header_str.len() < 16 {
            return Err(Box::<dyn Error>::from(
                "ERROR TR-31 HEADER: Invalid data length",
            ));
        }

        let version_id = header_str[0..1].to_string();
        let kb_length = header_str[1..5]
            .parse::<u16>()
            .map_err(|_| Box::<dyn Error>::from("ERROR TR-31 HEADER: Invalid key block length"))?;
        let key_usage = header_str[5..7].to_string();
        let algorithm = header_str[7..8].to_string();
        let mode_of_use = header_str[8..9].to_string();
        let key_version_number = header_str[9..11].to_string();
        let exportability = header_str[11..12].to_string();
        let num_optional_blocks = header_str[12..14].parse::<u8>().map_err(|_| {
            Box::<dyn Error>::from("ERROR TR-31 HEADER: Invalid number of optional blocks")
        })?;
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
            return Err(
                "ERROR TR-31 HEADER: Invalid header length containing optional blocks".into(),
            );
        }

        if num_optional_blocks > 0 {
            let opt_block_str = &header_str[16..];
            let opt_block_res = OptBlock::new_from_str(opt_block_str, num_optional_blocks as usize);

            if let Err(e) = opt_block_res {
                return Err(
                    format!("ERROR TR-31 HEADER: Failed to parse optional blocks: {}", e).into(),
                );
            }

            header.opt_blocks = Some(Box::new(opt_block_res.unwrap()));
        }

        Ok(header)
    }

    /// Export the `KeyBlockHeader` as a string representation.
    ///
    /// This function constructs a string that represents the key block header,
    /// adhering to the TR-31 standard. It validates that all fields of the header
    /// are properly assigned and not empty (except `num_opt_blocks`, which can be zero),
    /// and then formats each field into a string. The `kb_length` is formatted as
    /// a four-character string (e.g., "0160"), and `num_opt_blocks` is formatted as
    /// a two-character decimal string (e.g., "02"). If present, optional blocks are
    /// serialized and appended to the header string using their `export_str` method.
    ///
    /// # Returns
    ///
    /// A `Result` containing the string representation of the key block header.
    /// If any field is empty or `kb_length` is zero, or if an error occurs while
    /// exporting optional blocks, an error is returned as a boxed error.
    ///
    /// # Errors
    ///
    /// Returns an error if any field in the header is empty or if `kb_length` is zero.
    /// Also returns an error if there is a failure in exporting the optional blocks.
    pub fn export_str(&self) -> Result<String, Box<dyn Error>> {
        // Check for empty fields or zero length
        if self.version_id.is_empty()
            || self.key_usage.is_empty()
            || self.algorithm.is_empty()
            || self.mode_of_use.is_empty()
            || self.key_version_number.is_empty()
            || self.exportability.is_empty()
            || self.reserved_field.is_empty()
            || self.kb_length == 0
        {
            return Err(
                "ERROR TR-31 HEADER: Export failed due to empty field(s) or zero length".into(),
            );
        }

        let mut header_str = String::new();

        // Append each field to the header string
        header_str.push_str(&self.version_id());
        header_str.push_str(&format!("{:04}", self.kb_length()));
        header_str.push_str(&self.key_usage());
        header_str.push_str(&self.algorithm());
        header_str.push_str(&self.mode_of_use());
        header_str.push_str(&self.key_version_number());
        header_str.push_str(&self.exportability());
        header_str.push_str(&format!("{:02}", self.num_opt_blocks));
        header_str.push_str(&self.reserved_field());

        // Append optional blocks if present
        if let Some(ref opt_blocks) = self.opt_blocks {
            header_str.push_str(&opt_blocks.export_str()?);
        }

        Ok(header_str)
    }

    /// Set the version ID of the key block header.
    ///
    /// Validates the version ID against allowed values and sets the
    /// encryption block size based on the version ID. If the provided
    /// version ID is not allowed, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The version ID to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_version_id(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        if Self::ALLOWED_VERSION_IDS.contains(&value) {
            self.version_id = value.to_string();
            Ok(())
        } else {
            Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Invalid version ID: {}",
                value
            )))
        }
    }

    /// Get the version ID of the key block header.
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    /// Set the key block length.
    ///
    /// Validates the length to ensure it does not exceed the maximum allowed value.
    /// If the length is invalid, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The length of the key block to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the length is valid, or an `Err` with a boxed error.
    pub fn set_kb_length(&mut self, value: u16) -> Result<(), Box<dyn Error>> {
        if value > 9999 {
            Err(Box::<dyn Error>::from(
                "ERROR TR-31 HEADER: Invalid key block length",
            ))
        } else {
            self.kb_length = value;
            Ok(())
        }
    }

    /// Get the key block length.
    pub fn kb_length(&self) -> u16 {
        self.kb_length
    }

    /// Set the key usage of the key block header.
    ///
    /// Validates the key usage against allowed values. If the provided key usage is not
    /// allowed, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The key usage to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_key_usage(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        if Self::ALLOWED_KEY_USAGES.contains(&value) {
            self.key_usage = value.to_string();
            Ok(())
        } else {
            Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Invalid key usage: {}",
                value
            )))
        }
    }

    /// Get the key usage of the key block header.
    pub fn key_usage(&self) -> &str {
        &self.key_usage
    }

    /// Set the algorithm of the key block header.
    ///
    /// Validates the algorithm against allowed values. If the provided algorithm is not
    /// allowed, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The algorithm to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_algorithm(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        if Self::ALLOWED_ALGORITHMS.contains(&value) {
            self.algorithm = value.to_string();
            Ok(())
        } else {
            Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Invalid algorithm: {}",
                value
            )))
        }
    }

    /// Get the algorithm of the key block header.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Set the mode of use for the key block header.
    ///
    /// Validates the mode of use against allowed values. If the provided mode of use is not
    /// allowed, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The mode of use to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_mode_of_use(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        if Self::ALLOWED_MODES_OF_USE.contains(&value) {
            self.mode_of_use = value.to_string();
            Ok(())
        } else {
            Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Invalid mode of use: {}",
                value
            )))
        }
    }

    /// Get the mode of use of the key block header.
    pub fn mode_of_use(&self) -> &str {
        &self.mode_of_use
    }

    /// Set the key version number of the key block header.
    ///
    /// Validates that the key version number consists of 2 ASCII characters. If the provided key version
    /// number is invalid, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The key version number to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_key_version_number(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        if value.len() != 2 {
            return Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Key version number must consist of 2 ASCII characters: {}",
                value
            )));
        }
        if !value.chars().all(|c| c.is_ascii()) {
            return Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Key version number must consist of ASCII characters: {}",
                value
            )));
        }
        self.key_version_number = value.to_string();
        Ok(())
    }

    /// Get the key version number of the key block header.
    pub fn key_version_number(&self) -> &str {
        &self.key_version_number
    }

    /// Set the exportability of the key block header.
    ///
    /// Validates the exportability against allowed values. If the provided exportability is not
    /// allowed, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The exportability to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_exportability(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        if Self::ALLOWED_EXPORTABILITIES.contains(&value) {
            self.exportability = value.to_string();
            Ok(())
        } else {
            Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Invalid exportability: {}",
                value
            )))
        }
    }

    /// Get the exportability of the key block header.
    pub fn exportability(&self) -> &str {
        &self.exportability
    }

    /// Set the number of optional blocks in the key block header.
    ///
    /// Validates that the number does not exceed the maximum limit. If the provided number
    /// of optional blocks is invalid, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The number of optional blocks to be set.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_num_optional_blocks(&mut self, value: u8) -> Result<(), Box<dyn Error>> {
        if value > 99 {
            return Err(Box::<dyn Error>::from(
                "ERROR TR-31 HEADER: Number of opt blocks value is too large",
            ));
        }
        self.num_opt_blocks = value;
        Ok(())
    }

    /// Get the number of optional blocks in the key block header.
    pub fn num_optional_blocks(&self) -> u8 {
        self.num_opt_blocks
    }

    /// Set the value for the reserved field in the key block header.
    ///
    /// Validates that the reserved field is set to the correct value, which should be "00".
    /// If the provided value is invalid, returns an error.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to be set for the reserved field.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the value is valid, or an `Err` with a boxed error.
    pub fn set_reserved_field(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        if value == "00" {
            self.reserved_field = value.to_string();
            Ok(())
        } else {
            return Err(Box::<dyn Error>::from(format!(
                "ERROR TR-31 HEADER: Invalid value for reserved field: {}",
                value.to_string()
            )));
        }
    }

    /// Get the value of the reserved field in the key block header.
    pub fn reserved_field(&self) -> &str {
        &self.reserved_field
    }

    /// Set the optional blocks for the key block header and update the number of optional blocks.
    ///
    /// This method sets the `opt_blocks` field with the provided optional blocks and updates
    /// the `num_opt_blocks` field based on the count of the optional blocks.
    ///
    /// # Arguments
    ///
    /// * `opt_blocks` - An `Option<Box<OptBlock>>` representing the optional blocks.
    pub fn set_opt_blocks(&mut self, opt_blocks: Option<Box<OptBlock>>) {
        self.opt_blocks = opt_blocks;

        // Reset the count of optional blocks
        self.num_opt_blocks = 0;

        // If there are optional blocks, count them
        if let Some(ref opt_block) = self.opt_blocks {
            let mut current_block: &OptBlock = opt_block.as_ref();

            self.num_opt_blocks = 1; // Counting the first block

            // Iterate through the chain of optional blocks to count them
            while let Some(next_block) = current_block.next() {
                self.num_opt_blocks += 1;
                current_block = next_block;
            }
        }
    }

    /// Append a linked list of `OptBlock` instances to the end of the existing
    /// optional blocks in the `KeyBlockHeader`.
    ///
    /// # Arguments
    ///
    /// * `opt_block_to_append` - The head of the linked list of `OptBlock` instances to be appended.
    ///
    /// # WARNING!
    ///
    /// Not fully tested!
    /// TODO: Add more unit tests for this function.
    pub fn append_opt_blocks(&mut self, opt_block_to_append: OptBlock) {
        // Count the number of blocks in the provided list
        let mut additional_blocks_count = 1;
        let mut current_block = &opt_block_to_append;
        while let Some(next_block) = current_block.next() {
            additional_blocks_count += 1;
            current_block = next_block;
        }

        // Append the provided list to the existing optional blocks
        match &mut self.opt_blocks {
            Some(existing_opt_block) => {
                existing_opt_block.append(opt_block_to_append);
            }
            None => {
                self.opt_blocks = Some(Box::new(opt_block_to_append));
            }
        }

        // Update the count of optional blocks
        self.num_opt_blocks += additional_blocks_count;
    }

    /// Get a reference to the optional blocks.
    pub fn opt_blocks(&self) -> &Option<Box<OptBlock>> {
        &self.opt_blocks
    }

    /// Get the header length including the length of optional blocks.
    pub fn len(&self) -> usize {
        // Minimum length of header without optional blocks: 16
        let mut header_length = 16;

        // Add the length of optional blocks if they exist
        if let Some(ref opt_blocks) = self.opt_blocks {
            header_length += opt_blocks.total_length();
        }

        header_length
    }

    /// Finalize the key block header to ensure its length is a multiple of the underlying cipher block size.
    /// A padding block with ID "PB" is appended if necessary.
    pub fn finalize(&mut self) -> Result<(), Box<dyn Error>> {
        let block_size = if self.version_id == "D" { 16 } else { 8 };
        let header_length = self.len();

        // Only proceed if there are optional blocks and the header length is not already a multiple of block size
        if let Some(ref mut opt_blocks) = self.opt_blocks {
            if header_length % block_size != 0 {
                let mut padding_needed = block_size - (header_length % block_size);

                // Make sure the padding block consists minimum of 6 bytes (ID, length field and at
                // least two 0s) and append otherwise.
                if padding_needed < 6 {
                    padding_needed += block_size;
                }

                // Length of the padding data without ID and length field.
                let padding_data_length = padding_needed - 4;

                let padding_data = "0".repeat(padding_data_length);
                let padding_block = OptBlock::new("PB", &padding_data, None)?;

                // Append the padding block
                opt_blocks.append(padding_block);

                // Update the number of optional blocks
                self.num_opt_blocks += 1;
            }
        }

        Ok(())
    }
}
