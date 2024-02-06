use std::cmp::max;
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
    // if key_len > TR31_MAX_KEY_LENGTH {
    //     return Err("ERROR TR-31 PAYLOAD: Key length too long".into());
    // }
    // TODO: Calculate max length of key to fit the length field...

    let raw_key_section_length = 2 + key_len;

    let effective_key_length = max(key_len, masked_key_length);
    let total_payload_length = ((2 + effective_key_length + (cipher_block_length - 1))
        / cipher_block_length)
        * cipher_block_length;

    let padding_length = total_payload_length - raw_key_section_length;

    let mut payload = Vec::with_capacity(total_payload_length);

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
