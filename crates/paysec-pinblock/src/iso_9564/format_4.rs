//! ISO 9564 format 4 PIN block encoding, encryption, decryption, and decoding.
//!
//! This module provides functionality for handling PIN blocks according to
//! ISO 9564 format 4.
//!
//! Format 4 is intended for use with AES and binds the encoded PIN field to a
//! Primary Account Number (PAN). The cryptographic operations themselves are
//! not implemented by this crate. Instead, they are delegated to a provider
//! implementing [`paysec_crypto::AesBlockCipher`].
//!
//! This allows callers to select an appropriate cryptographic backend, such as
//! a software implementation for testing or, in the future, a provider backed
//! by an HSM or another cryptographic service.
//!
//! # Operations
//!
//! The module provides functionality to:
//!
//! - encode a PIN into an ISO 9564 format 4 PIN field,
//! - decode an ISO 9564 format 4 PIN field,
//! - encode a PAN into an ISO 9564 format 4 PAN field,
//! - encipher a format 4 PIN block using an AES-capable provider,
//! - decipher a format 4 PIN block using an AES-capable provider.
//!
//! The format 4 enciphering procedure is:
//!
//! 1. Encode the PIN field.
//! 2. Encode the PAN field.
//! 3. Encrypt the PIN field with AES.
//! 4. XOR the encrypted result with the PAN field.
//! 5. Encrypt the XOR result with AES.
//!
//! Deciphering performs the corresponding operations in reverse.
//!
//! # Example
//!
//! ```
//! use paysec_crypto_soft_aes::SoftAesProvider;
//! use paysec_pinblock::{
//!     decipher_pinblock_iso_4,
//!     encipher_pinblock_iso_4,
//! };
//!
//! let provider = SoftAesProvider::new();
//!
//! let key = hex::decode("00112233445566778899AABBCCDDEEFF")
//!     .expect("Invalid key hex");
//!
//! let pin = "1234";
//! let pan = "1234567890123456789";
//! let rnd_seed = vec![0xFF; 8];
//!
//! let encrypted_pin_block = encipher_pinblock_iso_4(
//!     &provider,
//!     key.as_slice(),
//!     pin,
//!     pan,
//!     rnd_seed,
//! )
//! .expect("Failed to encipher PIN block");
//!
//! let encrypted_pin_block_hex =
//!     hex::encode(&encrypted_pin_block).to_uppercase();
//!
//! assert_eq!(
//!     encrypted_pin_block_hex,
//!     "28B41FDDD29B743E93124BD8E32D921E"
//! );
//!
//! let decrypted_pin = decipher_pinblock_iso_4(
//!     &provider,
//!     key.as_slice(),
//!     &encrypted_pin_block,
//!     pan,
//! )
//! .expect("Failed to decipher PIN block");
//!
//! assert_eq!(decrypted_pin, pin);
//! ```
//!
//! # Security
//!
//! This crate defines the ISO 9564 format 4 processing logic but does not
//! prescribe a concrete cryptographic implementation.
//!
//! The security properties of AES operations therefore depend on the selected
//! [`paysec_crypto::AesBlockCipher`] provider.
//!
//! The caller is also responsible for providing the random data used when
//! encoding the PIN field. This module does not generate randomness or assess
//! the entropy quality of the supplied random seed.
//!
//! This library is primarily intended for payment-security tooling, testing,
//! and test-data generation. Production use should employ an appropriately
//! secured cryptographic implementation, such as an HSM where required.

use crate::utils::{left_pad_str, right_pad_str, xor_byte_arrays};

use paysec_crypto::AesBlockCipher;
use std::error::Error;

const ISO4_PIN_BLOCK_LENGTH: usize = 16;
const ISO4_RANDOM_SEED_LENGTH: usize = 8;

/// Encode a PIN into an ISO 9564 format 4 PIN field.
///
/// The resulting PIN field is 16 bytes long.
///
/// The first half contains:
///
/// - the format identifier,
/// - the PIN length,
/// - the PIN digits encoded as BCD,
/// - `0xA` filler nibbles.
///
/// The second half contains the first eight bytes of the supplied random seed.
///
/// # Parameters
///
/// * `pin` - ASCII-encoded PIN consisting of 4 to 12 numeric digits.
/// * `rnd_seed` - Random data used for the second half of the PIN field.
///   At least 8 bytes must be supplied.
///
/// # Returns
///
/// A 16-byte ISO 9564 format 4 PIN field.
///
/// # Errors
///
/// Returns an error if:
///
/// - the PIN is shorter than 4 digits,
/// - the PIN is longer than 12 digits,
/// - the PIN contains non-numeric characters,
/// - fewer than 8 random bytes are supplied.
pub fn encode_pin_field_iso_4(
    pin: &str,
    rnd_seed: Vec<u8>,
) -> Result<[u8; ISO4_PIN_BLOCK_LENGTH], Box<dyn Error>> {
    if pin.len() < 4 || pin.len() > 12 || !pin.chars().all(char::is_numeric) {
        return Err("PIN BLOCK ISO 4 ERROR: PIN must be between 4 and 12 digits long".into());
    }

    if rnd_seed.len() < ISO4_RANDOM_SEED_LENGTH {
        return Err("PIN BLOCK ISO 4 ERROR: Random seed must be at least 8 bytes long".into());
    }

    let mut pin_field = [0u8; ISO4_PIN_BLOCK_LENGTH];

    // Control field set to format 4 followed by the PIN length.
    pin_field[0] = 0x40 | pin.len() as u8;

    // Encode PIN digits as BCD.
    for (i, c) in pin.chars().enumerate() {
        let digit = c.to_digit(10).unwrap() as u8;

        pin_field[1 + i / 2] |= if i % 2 == 0 { digit << 4 } else { digit };
    }

    // Fill the remaining PIN-area nibbles with 0xA.
    for i in pin.len()..14 {
        pin_field[1 + i / 2] |= if i % 2 == 0 { 0xA0 } else { 0x0A };
    }

    // Fill the second half with the first eight bytes of random data.
    pin_field[8..].copy_from_slice(&rnd_seed[..ISO4_RANDOM_SEED_LENGTH]);

    Ok(pin_field)
}

/// Decode a PIN from an ISO 9564 format 4 PIN field.
///
/// The function validates the format identifier, PIN length, PIN digits, and
/// filler nibbles before returning the decoded PIN.
///
/// # Parameters
///
/// * `pin_field` - Encoded ISO 9564 format 4 PIN field. It must be exactly
///   16 bytes long.
///
/// # Returns
///
/// The decoded PIN as a [`String`].
///
/// # Errors
///
/// Returns an error if:
///
/// - the PIN field is not exactly 16 bytes long,
/// - the format identifier is not format 4,
/// - the encoded PIN length is outside the range 4 to 12,
/// - a PIN digit contains an invalid BCD value,
/// - a filler nibble is not `0xA`.
pub fn decode_pin_field_iso_4(pin_field: &[u8]) -> Result<String, Box<dyn Error>> {
    if pin_field.len() != ISO4_PIN_BLOCK_LENGTH {
        return Err("PIN BLOCK ISO 4 ERROR: PIN field must be 16 bytes long".into());
    }

    // The high nibble identifies ISO format 4.
    if pin_field[0] >> 4 != 0x4 {
        return Err(format!(
            "PIN BLOCK ISO 4 ERROR: PIN block is not ISO format 4: control field `{}`",
            pin_field[0] >> 4
        )
        .into());
    }

    // The low nibble contains the PIN length.
    let pin_len = (pin_field[0] & 0x0F) as usize;

    if !(4..=12).contains(&pin_len) {
        return Err(format!(
            "PIN BLOCK ISO 4 ERROR: PIN length must be between 4 and 12: `{}`",
            pin_len
        )
        .into());
    }

    let mut pin = String::with_capacity(pin_len);

    for i in 0..pin_len {
        let digit = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if digit > 9 {
            return Err("PIN BLOCK ISO 4 ERROR: PIN contains invalid digit".into());
        }

        pin.push(char::from(b'0' + digit));
    }

    // All unused PIN-area nibbles must contain 0xA.
    for i in pin_len..14 {
        let filler = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if filler != 0xA {
            return Err("PIN BLOCK ISO 4 ERROR: PIN block filler is incorrect".into());
        }
    }

    Ok(pin)
}

/// Encode a Primary Account Number into an ISO 9564 format 4 PAN field.
///
/// The resulting PAN field is 16 bytes long and is used during format 4 PIN
/// block enciphering and deciphering.
///
/// # Parameters
///
/// * `pan` - ASCII-encoded PAN consisting of 1 to 19 numeric digits.
///
/// # Returns
///
/// A 16-byte ISO 9564 format 4 PAN field.
///
/// # Errors
///
/// Returns an error if:
///
/// - the PAN is empty,
/// - the PAN contains more than 19 digits,
/// - the PAN contains non-numeric characters,
/// - hexadecimal decoding of the constructed PAN field fails.
pub fn encode_pan_field_iso_4(pan: &str) -> Result<[u8; ISO4_PIN_BLOCK_LENGTH], Box<dyn Error>> {
    if pan.is_empty() || pan.len() > 19 || !pan.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN BLOCK ISO 4 ERROR: PAN must be between 1 and 19 digits long.".into());
    }

    let pan_len = if pan.len() > 12 {
        (pan.len() - 12).to_string()
    } else {
        "0".to_string()
    };

    let pan_padded = left_pad_str(pan, 12, '0');

    let pan_field = pan_len + &pan_padded;

    let pan_field_hex = right_pad_str(&pan_field, 32, '0');

    let pan_bytes = hex::decode(&pan_field_hex)?;

    Ok(pan_bytes
        .as_slice()
        .try_into()
        .expect("Invalid length for PAN field conversion"))
}

/// Encipher an ISO 9564 format 4 PIN block.
///
/// Cryptographic operations are delegated to the supplied
/// [`AesBlockCipher`] provider.
///
/// The provider determines how the key is represented. A software provider may
/// accept raw key bytes, while another implementation may use an opaque key
/// handle.
///
/// # Parameters
///
/// * `provider` - Cryptographic provider used for AES block encryption.
/// * `key` - Provider-specific AES key.
/// * `pin` - ASCII-encoded PIN consisting of 4 to 12 numeric digits.
/// * `pan` - ASCII-encoded PAN consisting of 1 to 19 numeric digits.
/// * `rnd_seed` - Random data used when encoding the PIN field. At least
///   8 bytes must be supplied.
///
/// # Returns
///
/// The encrypted 16-byte PIN block as a [`Vec<u8>`].
///
/// # Errors
///
/// Returns an error if:
///
/// - the PIN is invalid,
/// - the PAN is invalid,
/// - fewer than 8 random bytes are supplied,
/// - an intermediate block cannot be constructed,
/// - the cryptographic provider reports an encryption error.
pub fn encipher_pinblock_iso_4<P, K: ?Sized>(
    provider: &P,
    key: &K,
    pin: &str,
    pan: &str,
    rnd_seed: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>>
where
    P: AesBlockCipher<K>,
{
    // Step 1: Encode PIN and PAN fields.
    let pin_field = encode_pin_field_iso_4(pin, rnd_seed)?;
    let pan_field = encode_pan_field_iso_4(pan)?;

    // Step 2: Encrypt the PIN field to produce intermediate block A.
    let intermediate_block_a = provider.encrypt_block(key, &pin_field)?;

    // Step 3: XOR intermediate block A with the PAN field to produce
    // intermediate block B.
    let intermediate_block_b = xor_byte_arrays(&intermediate_block_a, &pan_field)?;

    let intermediate_block_b: [u8; ISO4_PIN_BLOCK_LENGTH] = intermediate_block_b
        .try_into()
        .map_err(|_| "PIN BLOCK ISO 4 ERROR: Intermediate block must be 16 bytes long")?;

    // Step 4: Encrypt intermediate block B.
    let encrypted_block = provider.encrypt_block(key, &intermediate_block_b)?;

    // Step 5: Return the final encrypted PIN block.
    Ok(encrypted_block.to_vec())
}

/// Decipher an ISO 9564 format 4 PIN block.
///
/// Cryptographic operations are delegated to the supplied
/// [`AesBlockCipher`] provider.
///
/// The provider determines how the key is represented. A software provider may
/// accept raw key bytes, while another implementation may use an opaque key
/// handle.
///
/// # Parameters
///
/// * `provider` - Cryptographic provider used for AES block decryption.
/// * `key` - Provider-specific AES key.
/// * `pin_block` - Encrypted format 4 PIN block. It must be exactly 16 bytes.
/// * `pan` - ASCII-encoded PAN used when the PIN block was created.
///
/// # Returns
///
/// The decoded PIN as a [`String`].
///
/// # Errors
///
/// Returns an error if:
///
/// - the encrypted PIN block is not exactly 16 bytes,
/// - the PAN is invalid,
/// - an intermediate block cannot be constructed,
/// - the cryptographic provider reports a decryption error,
/// - the resulting PIN field is invalid.
pub fn decipher_pinblock_iso_4<P, K: ?Sized>(
    provider: &P,
    key: &K,
    pin_block: &[u8],
    pan: &str,
) -> Result<String, Box<dyn Error>>
where
    P: AesBlockCipher<K>,
{
    if pin_block.len() != ISO4_PIN_BLOCK_LENGTH {
        return Err("PIN BLOCK ISO 4 ERROR: PIN block must be exactly 16 bytes long".into());
    }

    let pin_block: &[u8; ISO4_PIN_BLOCK_LENGTH] = pin_block
        .try_into()
        .map_err(|_| "PIN BLOCK ISO 4 ERROR: PIN block must be exactly 16 bytes long")?;

    // Step 1: Decrypt the PIN block to obtain intermediate block B.
    let intermediate_block_b = provider.decrypt_block(key, pin_block)?;

    // Step 2: Encode the PAN field.
    let pan_field = encode_pan_field_iso_4(pan)?;

    // Step 3: XOR intermediate block B with the PAN field to recover
    // intermediate block A.
    let intermediate_block_a = xor_byte_arrays(&intermediate_block_b, &pan_field)?;

    let intermediate_block_a: [u8; ISO4_PIN_BLOCK_LENGTH] = intermediate_block_a
        .try_into()
        .map_err(|_| "PIN BLOCK ISO 4 ERROR: Intermediate block must be 16 bytes long")?;

    // Step 4: Decrypt intermediate block A to recover the PIN field.
    let pin_field = provider.decrypt_block(key, &intermediate_block_a)?;

    // Step 5: Decode the plaintext PIN field.
    decode_pin_field_iso_4(&pin_field)
}
