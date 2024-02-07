use super::key_block_header::KeyBlockHeader;
use super::key_derivations::derive_keys_version_d;
use super::payload::construct_payload;
use soft_aes::aes::{aes_cmac, aes_enc_cbc};
use std::error::Error;

const TR31_D_MAC_LEN: usize = 16;
const TR31_D_BLOCK_LEN: usize = 16;

/// Wrap a cryptographic key according to TR-31 key block format version 'D'.
///
/// This function implements the TR-31 key block wrapping mechanism for version 'D'. It involves
/// several steps: key derivation, payload construction, MAC computation, encryption, and
/// assembly of the final key block. It takes the key block protection key (KBPK), a key block
/// header, the key to be protected, a masked key length, and a random seed as inputs.
///
/// # Arguments
/// * `kbpk` - Key Block Protection Key used for deriving the encryption (KBEK) and
///            authentication (KBAK) keys.
/// * `header` - KeyBlockHeader instance containing metadata for the key block.
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
    let total_block_length = header.header_length() + (payload.len() * 2) + (TR31_D_MAC_LEN * 2);

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
