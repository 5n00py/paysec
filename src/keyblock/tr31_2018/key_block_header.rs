use super::opt_block::OptBlock;

use std::error::Error;

/// Represents the header of a TR-31 Key Block.
///
/// The `KeyBlockHeader` struct encapsulates all the necessary information
/// required to define the characteristics of a key block according to
/// TR-31 standards. It includes fields like version ID, key usage,
/// algorithm, mode of use, etc., and supports optional blocks for
/// additional data.
/// The struct contains also fields used for internal processing and
/// calculations that are not part of the final key block header in the encoded
/// key block.
#[derive(Debug, PartialEq)]
pub struct KeyBlockHeader {
    /// Identifies the version of the key block, determining its cryptographic
    /// protection method and the layout.
    version_id: String,

    /// Specifies the total length of the key block after encoding,
    /// including header, encrypted data, and MAC.
    kb_length: u16,

    /// Indicates the intended function of the protected key/sensitive data.
    key_usage: String,

    /// Specifies the algorithm to be used for the protected key.
    algorithm: String,

    /// Defines the operation that the protected key can perform.
    mode_of_use: String,

    /// Optional version number of the key, used for key management.
    key_version_number: String,

    /// Indicates the exportability of the protected key.
    exportability: String,

    /// Number of optional blocks included in the key block.
    num_opt_blocks: u8,

    /// Reserved for future use, currently filled with zero characters.
    reserved_field: String,

    /// Contains additional optional blocks of data if present.
    opt_blocks: Option<Box<OptBlock>>,

    /// Length of the header part of the key block, used for internal processing
    /// and not part of the final key block.
    header_length: usize,

    /// Size of the encryption block used in the key block, used for internal
    /// calculations related to encryption and padding mechanisms, not part of
    /// the final key block header.
    enc_block_size: usize,
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

            header_length: 0,
            enc_block_size: 0,
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

        header.header_length = 16;

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

        header.header_length = 16;

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
            header.header_length += header.opt_blocks.as_ref().unwrap().total_length();
        }

        Ok(header)
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

            // Set block size based on version ID
            self.enc_block_size = if value == "A" { 16 } else { 8 };

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

    /// Get a reference to the optional blocks.
    pub fn opt_blocks(&self) -> &Option<Box<OptBlock>> {
        &self.opt_blocks
    }

    /// Get the value of the header length
    pub fn header_length(&self) -> usize {
        self.header_length
    }
}
