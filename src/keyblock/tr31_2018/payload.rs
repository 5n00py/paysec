use std::error::Error;

/// Constructs the payload for a TR-31 key block.
///
/// This function creates the payload to be encrypted in a TR-31 key block.
/// It includes the key length (in bits), the key itself, and the necessary padding.
/// The padding length is calculated to ensure the total payload length is a multiple
/// of the cipher block size. A random seed is used for padding to enhance security.
///
/// # Arguments
///
/// * `key`: The key or sensitive data being protected.
/// * `masked_key_length`: The minimum length for the key data, used to mask the true length of shorter keys.
/// * `cipher_block_length`: The block length of the encryption cipher (e.g., 16 for AES).
/// * `random_seed`: Random data used for padding. Must be at least as long as the calculated padding length.
///
/// # Returns
///
/// A `Result` containing the constructed payload as a `Vec<u8>` if successful, or an error if any conditions are not met.
///
/// # Errors
///
/// This function returns an error if the key length exceeds the TR-31 maximum length or if the
/// provided random seed is too short for the required padding.
pub fn construct_payload(
    key: &[u8],
    masked_key_length: usize,
    cipher_block_length: usize,
    random_seed: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let key_len = key.len();

    // Calculate the padding length
    let padding_length = calculate_padding_length(key_len, masked_key_length, cipher_block_length)?;

    let mut payload = Vec::with_capacity(key_len + 2 + padding_length);

    // Write the key length in bits (16-bit big endian)
    payload.extend_from_slice(&(8 * key_len as u16).to_be_bytes());

    // Append the actual key
    payload.extend_from_slice(key);

    // Use the provided random seed for the padding
    if random_seed.len() < padding_length {
        return Err(
            "ERROR TR-31 PAYLOAD: The provided random seed is too short for the padding requirement"
                .into(),
        );
    }

    // Truncate random_seed to padding_length and add it as padding to payload
    payload.extend_from_slice(&random_seed[..padding_length]);

    Ok(payload)
}

/// Extract the secret key from a TR-31 payload.
///
/// This function reads the key length (in bits) from the first 2 bytes of the payload,
/// then extracts the key based on this length. The function assumes that the payload is
/// correctly formatted according to TR-31 specifications.
///
/// # Arguments
///
/// * `payload`: The TR-31 payload containing the key length, key, and padding.
///
/// # Returns
///
/// A `Result` containing the extracted key as a `Vec<u8>` if successful, or an error if the payload is incorrectly formatted.
///
/// # Errors
///
/// This function returns an error if the payload length is too short to contain a valid key length and key.
pub fn extract_key_from_payload(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if payload.len() < 2 {
        return Err("ERROR TR-31 PAYLOAD: Payload too short to contain valid key length".into());
    }

    // Read the key length in bits from the first 2 bytes and convert to bytes
    let key_length_bits = u16::from_be_bytes([payload[0], payload[1]]);
    let key_length_bytes = (key_length_bits / 8) as usize;

    // Check if the payload has enough data for the key
    if payload.len() < 2 + key_length_bytes {
        return Err("ERROR TR-31 PAYLOAD: Payload too short for the specified key length".into());
    }

    // Extract the key based on the calculated length
    let key = payload[2..2 + key_length_bytes].to_vec();

    Ok(key)
}

/// Calculate the padding length for a TR-31 key block payload.
///
/// # Arguments
/// * `key_len`: The length of the key in bytes.
/// * `masked_key_length`: The minimum length for the key data, used to mask the true length of shorter keys.
/// * `cipher_block_length`: The block length of the encryption cipher (e.g., 16 for AES).
///
/// # Returns
/// The padding length required for the payload.
///
/// # Errors
/// Returns an error if the calculated total payload length or padding length is invalid.
pub fn calculate_padding_length(
    key_len: usize,
    masked_key_length: usize,
    cipher_block_length: usize,
) -> Result<usize, Box<dyn Error>> {
    let raw_key_section_length = 2 + key_len;
    let effective_key_length = std::cmp::max(key_len, masked_key_length);
    let total_payload_length = ((2 + effective_key_length + (cipher_block_length - 1))
        / cipher_block_length)
        * cipher_block_length;

    if total_payload_length < raw_key_section_length {
        return Err("ERROR TR-31 PAYLOAD: Invalid total payload length".into());
    }

    let padding_length = total_payload_length - raw_key_section_length;
    Ok(padding_length)
}
