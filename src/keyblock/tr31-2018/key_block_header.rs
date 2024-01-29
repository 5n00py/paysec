#[derive(Debug)]
struct KeyBlockHeader {
    version_id: char,           // 1AN
    block_length: String,       // 4N
    key_usage: String,          // 2AN
    algorithm: char,            // 1AN
    mode_of_use: char,          // 1AN
    key_version_number: String, // 2AN
    exportability: char,        // 1AN
    optional_blocks: String,    // 2N
    reserved: String,           // 2N, Reserved for future use
}

impl KeyBlockHeader {
    fn new(
        version_id: char,
        block_length: String,
        key_usage: String,
        algorithm: char,
        mode_of_use: char,
        key_version_number: String,
        exportability: char,
        optional_blocks: String,
    ) -> KeyBlockHeader {
        KeyBlockHeader {
            version_id,
            block_length,
            key_usage,
            algorithm,
            mode_of_use,
            key_version_number,
            exportability,
            optional_blocks,
            reserved: "00".to_string(), // Default value for reserved field
        }
    }

    // Function to encode the struct to bytes
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version_id as u8);
        bytes.extend(self.block_length.bytes());
        bytes.extend(self.key_usage.bytes());
        bytes.push(self.algorithm as u8);
        bytes.push(self.mode_of_use as u8);
        bytes.extend(self.key_version_number.bytes());
        bytes.push(self.exportability as u8);
        bytes.extend(self.optional_blocks.bytes());
        bytes.extend(self.reserved.bytes());
        bytes
    }

    // Function to decode bytes to the struct
    fn decode(_bytes: &[u8]) -> Result<KeyBlockHeader, &'static str> {
        // TODO: Implementation
        Err("Not yet implemented")
    }
}
