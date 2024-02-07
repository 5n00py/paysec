//! Module for TR-31 Key Block Wrapping and Unwrapping.
//!
//! This module provides functions for wrapping and unwrapping cryptographic keys according to
//! the TR-31 key block format, version 'D'. TR-31 defines a method consistent with the requirements
//! of ANS X9.24 Retail Financial Services Symmetric Key Management Part 1 for the secure exchange of
//! keys and other sensitive data between two devices that share a symmetric key exchange key. This
//! method may also be used for the storage of keys under a symmetric key.
//!
//! # Key Block Format
//!
//! The Key Block consists of three parts:
//! 1. The Key Block Header (KBH) contains attribute information about the key and the key block and is not encrypted.
//!     - The first section is 16 bytes with a fixed format.
//!     - The second section is optional.
//! 2. The confidential data which will be encrypted:
//!     - Two bytes indicating the key length.
//!     - The key/sensitive data that is being exchanged and/or stored.
//!     - Random padding up to a fixed length or masked length.
//! 3. A MAC, which is 16 bytes long.
//!
//! # Key Block Wrapping Process
//!
//! The encryption key and authentication key are derived from the Key Block Protection Key (KBPK) using CMAC
//! as a pseudorandom function. The key block construction process includes key derivation, payload construction,
//! MAC computation, encryption, and assembly of the final key block.
//!
//! # Supported Version
//!
//! Only version 'D' is supported for key block wrapping and unwrapping by implementation.
//!
//! # Usage
//!
//! This module is used in systems where secure exchange and storage of cryptographic keys is crucial,
//! such as banking and financial systems, secure communications, and others.
//!
//! # Module Limitations and Security Considerations
//!
//! - The module does not enforce block IDs or their contents beyond the check of supported values.
//! - It does not enforce or verify key block usage, algorithm, mode of use, etc., except for
//!   format requirements.
//! - The provided key block header must belong to the key block and cannot be
//!   substituted which is enforced by this implementation.
//! - Upon successful validation/unwrapping, the module provides parsed key block
//!   header properties.
//! - The random seed must be provided externally; this library does not assess
//!   entropy or random number generation quality.
//! - Cryptographic operations use the `soft-aes` crate, which (currently) lacks
//!   protections against side-channel attacks.
//! - In a production environment, using a hardware security module (HSM) for
//!   core cryptographic operations and random number generation is recommended.
//! - Compliance with specific security standards such as PCI DSS, PCI P2PE and PCI PIN
//!   is not explicitly considered or implemented in this library.
//! - Proper management of cryptographic keys, including those used for protection (like KBPK),
//!   is crucial. Users are responsible for ensuring that key management practices meet
//!   the necessary security requirements.
//!
//! # Disclaimer
//!
//! - This library is provided "as is", with no warranty or guarantees regarding its security or
//!   effectiveness in a production environment.
//!
//! # Example 1: Wrapping and Unwrapping a Key:
//! ```
//! use paysec::keyblock::{tr31_wrap, tr31_unwrap};
//! use paysec::keyblock::{KeyBlockHeader, OptBlock};
//! use hex;
//!
//! // Step 1: Building a Header
//! let header = KeyBlockHeader::new_with_values("D", "P0", "A", "E", "00", "E").unwrap();
//! // This creates a new KeyBlockHeader with specified values.
//!
//! // Step 2: Defining the Key to Protect
//! let key = hex::decode("3F419E1CB7079442AA37474C2EFBF8B8").unwrap();
//! // Now we have a key that we want to protect.
//!
//! // Step 3: Providing a Random Seed for Padding
//! let random_seed = hex::decode("1C2965473CE206BB855B01533782").unwrap();
//! // The random seed is used for generating padding in the payload.
//!
//! // Step 4: Setting the Masked Key Length
//! let masked_key_length = 0;
//! // No masking of the key length, so set to zero.
//!
//! // Step 5: Defining the Key Block Protection Key (KBPK)
//! let kbpk = hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();
//! // This is the key used for deriving the encryption and authentication keys.
//!
//! // Step 6: Wrapping the Key
//! let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();
//! // Wraps the key using the TR-31 key block format.
//!
//! // Step 7: Validating the Wrapped Key Block
//! let expected_key_block = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";
//! assert_eq!(key_block, expected_key_block, "Key block wrapping mismatch");
//! // Check if the wrapped key block matches the expected result.
//!
//! // Step 8: Unwrapping the Key Block
//! let unwrap_result = tr31_unwrap(&kbpk, &key_block);
//! assert!(unwrap_result.is_ok(), "Unwrapping failed");
//! let (unwrapped_header, unwrapped_key) = unwrap_result.unwrap();
//! // Unwraps the key block to retrieve the original key and header.
//!
//! // Step 9: Validating the Unwrapped Key
//! assert_eq!(unwrapped_key, key, "Key unwrapping mismatch");
//! // Ensure the unwrapped key matches the original key.
//! ```
//!
//! # Example 2: Wrapping and Unwrapping a Key with a Header String:
//! ```
//! use paysec::keyblock::{tr31_wrap_with_header_string, tr31_unwrap};
//! use hex;
//!
//! // Using a header string directly instead of a KeyBlockHeader instance.
//! // Note that the length of the key block can be "0000" or any value and will be updated later.
//! let header_str = "D0000P0AE00E0000";
//!
//! // The cryptographic key to be protected.
//! let key = hex::decode("3F419E1CB7079442AA37474C2EFBF8B8").unwrap();
//!
//! // Random seed used for generating padding in the payload.
//! let random_seed = hex::decode("1C2965473CE206BB855B01533782").unwrap();
//!
//! // Length used to mask the true length of short keys (0 for no masking).
//! let masked_key_length = 0;
//!
//! // Key Block Protection Key (KBPK).
//! let kbpk = hex::decode("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6").unwrap();
//!
//! // Wrapping the key using the header string.
//! let key_block = tr31_wrap_with_header_string(header_str, &kbpk, &key, masked_key_length, &random_seed).unwrap();
//!
//! // Expected wrapped key block for validation.
//! let expected_key_block = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";
//! assert_eq!(key_block, expected_key_block, "Key block wrapping mismatch");
//!
//! // Unwrapping the wrapped key block to retrieve the original key and header.
//! let unwrap_result = tr31_unwrap(&kbpk, &key_block);
//! assert!(unwrap_result.is_ok(), "Unwrapping failed");
//! let (unwrapped_header, unwrapped_key) = unwrap_result.unwrap();
//!
//! // Validating that the unwrapped key matches the original key.
//! assert_eq!(unwrapped_key, key, "Key unwrapping mismatch");
//! ```
//!
//! Example 3: Wrapping and Unwrapping a Key with Optional Blocks and Padding
//!
//! This example demonstrates wrapping and unwrapping a key using a header with optional blocks,
//! including the addition of a padding block to finalize the header.
//!
//! ```
//! use paysec::keyblock::{tr31_wrap, tr31_unwrap};
//! use paysec::keyblock::{KeyBlockHeader, OptBlock};
//! use hex;
//!
//! // Creating a header with one optional block.
//! let mut header = KeyBlockHeader::new_from_str("D0048P0TE00N0100KS1800604B120F9292800000").unwrap();
//!
//! // Finalizing the header by adding a padding block.
//! header.finalize().unwrap();
//!
//! // The cryptographic key to be protected.
//! let key = hex::decode("FFEEDDCCBBAA99887766554433221100").unwrap();
//!
//! // No masked length in this case.
//! let masked_key_length = 0;
//!
//! // Random seed used for generating padding in the payload.
//! let random_seed = hex::decode("223655F4BC798073D74B705B9FFB").unwrap();
//!
//! // Key Block Protection Key (KBPK).
//! let kbpk = hex::decode("00112233445566778899AABBCCDDEEFF0011223344556677").unwrap();
//!
//! // Wrapping the key using the header with optional blocks and padding.
//! let key_block = tr31_wrap(&kbpk, header, &key, masked_key_length, &random_seed).unwrap();
//!
//! // Expected wrapped key block for validation.
//! let expected_key_block = "D0144P0TE00N0200KS1800604B120F9292800000PB080000F2A795BB540447553D9FA3812E64E76A577DA04A1E0DD9FA9EFDE394BE936D4532BF5BA7E57063B63FCD90F9C2020F77";
//! assert_eq!(key_block, expected_key_block, "Key block wrapping mismatch");
//!
//! // Unwrapping the wrapped key block to retrieve the original key and header.
//! let unwrap_result = tr31_unwrap(&kbpk, &key_block);
//! assert!(unwrap_result.is_ok(), "Unwrapping failed");
//! let (unwrapped_header, unwrapped_key) = unwrap_result.unwrap();
//!
//! // Validating that the unwrapped key matches the original key.
//! assert_eq!(unwrapped_key, key, "Key unwrapping mismatch");
//! ```

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
///                      If this value is 0 or shorter then key.len() the length will not be
///                      masked.
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
