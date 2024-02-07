use super::key_block_header::KeyBlockHeader;
use super::key_derivations::derive_keys_version_d;
use super::payload::{construct_payload, extract_key_from_payload};
use soft_aes::aes::{aes_cmac, aes_dec_cbc, aes_enc_cbc};
use std::error::Error;

const TR31_D_MAC_LEN: usize = 16;
const TR31_D_BLOCK_LEN: usize = 16;

/// Wrap a cryptographic key according to TR-31 key block format version 'D'.
///
/// This function implements the TR-31 key block wrapping mechanism for version 'D'. It involves
/// several steps: key derivation, payload construction, MAC computation, encryption, and
/// assembly of the final key block. It takes the key block protection key (KBPK), a mutable
/// key block header, the key to be protected, a masked key length, and a random seed as inputs.
///
/// # Arguments
/// * `kbpk` - Key Block Protection Key used for deriving the encryption (KBEK) and
///            authentication (KBAK) keys.
/// * `header` - Mutable KeyBlockHeader instance containing metadata for the key block.
///              The `kb_length` field of the header can be 0 or any value. This function will
///              update this value with the actual key block length during the process.
/// * `key` - The cryptographic key or sensitive data to be protected.
/// * `masked_key_len` - Length used to mask the true length of short keys.
/// * `random_seed` - Random seed used for generating padding in the payload.
///
/// # Returns
/// A `Result` containing the TR-31 formatted key block as a String or an error if any
/// step in the key block construction process fails.
///
/// # Errors
/// Returns an error if:
/// * The key block version is not supported (currently only 'D' is implemented).
/// * The total key block length is not a multiple of the block size for the underlying
///   algorithms.
/// * There are issues with key derivation, payload construction, MAC computation, or encryption.
/// * The header or payload data are improperly formatted.
pub fn tr31_wrap(
    kbpk: &[u8],
    mut header: KeyBlockHeader,
    key: &[u8],
    masked_key_len: usize,
    random_seed: &[u8],
) -> Result<String, Box<dyn Error>> {
    if header.version_id() != "D" {
        return Err(format!(
            "ERROR TR-31: Key block version not supported by implementation: {}",
            header.version_id()
        )
        .into());
    }

    // Derive keys
    let (kbek, kbak) = derive_keys_version_d(kbpk)?;

    // Construct payload
    let payload = construct_payload(key, masked_key_len, TR31_D_BLOCK_LEN, random_seed)?;

    // Calculate total key block length ascii encoded
    let total_block_length = header.len() + (payload.len() * 2) + (TR31_D_MAC_LEN * 2);

    // Check if total_block_length is a multiple of TR31_D_BLOCK_LEN
    if total_block_length % TR31_D_BLOCK_LEN != 0 {
        return Err(format!(
            "ERROR TR-31: Total block length is not a multiple of block length: {}",
            TR31_D_BLOCK_LEN
        )
        .into());
    }

    // Update the block length in the header
    header.set_kb_length(total_block_length as u16)?;

    // Export the header as string
    let header_str = header.export_str()?;

    // Concatenate header as ascii bytes with the payload to get the mac input
    let mut mac_input = header_str.as_bytes().to_vec();
    mac_input.extend_from_slice(&payload);

    // Calculate the mac and encrypt the payload
    let mac = aes_cmac(&mac_input, &kbak)?;
    let iv: [u8; TR31_D_MAC_LEN] = mac[0..TR31_D_MAC_LEN]
        .try_into()
        .expect("ERROR TR-31: Mac slice with incorrect length");
    let encrypted_payload = aes_enc_cbc(&payload, &kbek, &iv, None)?;

    // Construct the complete key block in ascii
    let encrypted_payload_hex = hex::encode_upper(&encrypted_payload);
    let mac_hex = hex::encode_upper(&mac);
    let complete_key_block = format!("{}{}{}", header_str, encrypted_payload_hex, mac_hex);

    Ok(complete_key_block)
}

/// Wrap a cryptographic key according to TR-31 key block format version 'D' with a string header.
///
/// This function wraps a cryptographic key according to the TR-31 key block format version 'D'.
/// It takes a string representation of the key block header, the Key Block Protection Key (KBPK),
/// the key to be protected, a masked key length, and a random seed as inputs.
///
/// # Arguments
/// * `header_str` - String representation of the key block header.
/// * `kbpk` - Key Block Protection Key used for deriving the encryption (KBEK) and
///            authentication (KBAK) keys.
/// * `key` - The cryptographic key or sensitive data to be protected.
/// * `masked_key_len` - Length used to mask the true length of short keys.
/// * `random_seed` - Random seed used for generating padding in the payload.
///
/// # Returns
/// A `Result` containing the TR-31 formatted key block as a String or an error if any
/// step in the key block construction process fails.
///
/// # Errors
/// Returns an error if:
/// * The key block version is not supported (currently only 'D' is implemented).
/// * The total key block length is not a multiple of the of the block size for the underlying
///   algorithms.
/// * There are issues with key derivation, payload construction, MAC computation, or encryption.
/// * The header or payload data are improperly formatted.
pub fn tr31_wrap_with_header_string(
    header_str: &str,
    kbpk: &[u8],
    key: &[u8],
    masked_key_len: usize,
    random_seed: &[u8],
) -> Result<String, Box<dyn Error>> {
    let header = KeyBlockHeader::new_from_str(header_str)?;

    tr31_wrap(kbpk, header, key, masked_key_len, random_seed)
}

/// Unwrap a cryptographic key from a TR-31 key block format version 'D'.
///
/// This function implements the TR-31 key block unwrapping mechanism for version 'D'. It involves
/// several steps: key derivation, decryption, MAC verification, and payload processing.
///
/// # Arguments
/// * `kbpk` - Key Block Protection Key used for deriving the encryption (KBEK) and
///            authentication (KBAK) keys.
/// * `key_block` - The TR-31 formatted key block as a String.
///
/// # Returns
/// A `Result` containing the `KeyBlockHeader` and the extracted key as bytes, or an error if any
/// step in the key block unwrapping process fails.
///
/// # Errors
/// Returns an error if:
/// * The key block version is not supported (currently only 'D' is implemented).
/// * The MAC check fails.
/// * There are issues with key derivation, decryption, or payload processing.
/// * The header or payload data are improperly formatted.
pub fn tr31_unwrap(
    kbpk: &[u8],
    key_block: &str,
) -> Result<(KeyBlockHeader, Vec<u8>), Box<dyn Error>> {
    // Parse the header from the key block string
    let header = KeyBlockHeader::new_from_str(&key_block)?;
    let header_len = header.len();

    // Validate key block length
    let key_block_len = key_block.len();
    if key_block_len != header.kb_length() as usize {
        return Err("ERROR TR-31: Key block length does not match its length in the header".into());
    }

    // Ensure minimum key block length: Min. header + min. payload + mac length.
    let min_key_block_len = 16 + 2 * TR31_D_BLOCK_LEN + 2 * TR31_D_MAC_LEN;
    if key_block_len < min_key_block_len {
        return Err("ERROR TR-31: Key block length is below minimum required length".into());
    }

    // Validate the version ID
    if header.version_id() != "D" {
        return Err(format!(
            "ERROR TR-31: Key block version not supported by implementation: {}",
            header.version_id()
        )
        .into());
    }

    // Extract the encrypted payload and MAC from the key block
    let encrypted_payload_hex = &key_block[header_len..(key_block_len - TR31_D_MAC_LEN * 2)];
    let mac_hex = &key_block[(key_block_len - TR31_D_MAC_LEN * 2)..];

    // Derive keys
    let (kbek, kbak) = derive_keys_version_d(kbpk)?;

    // Decrypt the payload
    let encrypted_payload = hex::decode(encrypted_payload_hex)?;
    let mac = hex::decode(mac_hex)?;
    let iv: [u8; TR31_D_MAC_LEN] = mac[0..TR31_D_MAC_LEN]
        .try_into()
        .expect("ERROR TR-31: Mac slice with incorrect length");
    let decrypted_payload = aes_dec_cbc(&encrypted_payload, &kbek, &iv, None)?;

    // Verify the MAC
    let mut mac_input = key_block[..header_len].as_bytes().to_vec();
    mac_input.extend_from_slice(&decrypted_payload);
    let calculated_mac = aes_cmac(&mac_input, &kbak)?;
    if mac != calculated_mac {
        return Err("ERROR TR-31: MAC check failed".into());
    }

    // Extract the key from the decrypted payload
    let key = extract_key_from_payload(&decrypted_payload)?;

    Ok((header, key))
}
