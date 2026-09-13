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
//! a software implementation for testing or a provider backed by an HSM or
//! another cryptographic service.
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
//! # PIN Handling
//!
//! PIN values supplied for encoding and enciphering are accepted as `&str`
//! and validated before use.
//!
//! Plaintext PIN values produced by decoding or deciphering are returned as
//! [`crate::Pin`]. The `Pin` type:
//!
//! - guarantees that the value contains between 4 and 12 ASCII decimal digits,
//! - redacts its contents from debug output,
//! - zeroizes its owned string when dropped,
//! - requires explicit access through [`crate::Pin::expose_secret`] when the
//!   plaintext PIN digits are needed.
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
//!     hex::encode_upper(&encrypted_pin_block);
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
//! assert_eq!(
//!     decrypted_pin.expose_secret(),
//!     pin,
//! );
//! ```
//!
//! # Security
//!
//! This crate defines the ISO 9564 format 4 processing logic but does not
//! prescribe a concrete cryptographic implementation.
//!
//! The security properties of AES operations therefore depend on the selected
//! [`paysec_crypto::AesBlockCipher`] provider. A software provider may operate
//! directly on raw key material in process memory, while an HSM-backed
//! provider may instead operate on opaque key handles.
//!
//! Plaintext PIN values returned by decoding or deciphering are held in
//! [`crate::Pin`]. The wrapper redacts debug output and zeroizes its owned
//! string when dropped.
//!
//! Temporary plaintext PIN-field buffers created internally during enciphering
//! and deciphering are also zeroized when they leave scope.
//!
//! These protections provide defense in depth against accidental disclosure
//! and residual process-memory contents. They do not guarantee that the PIN
//! has never existed elsewhere in memory. For example, callers may retain
//! additional plaintext copies, and operating-system facilities such as swap,
//! crash dumps, or process-memory inspection are outside the scope of this
//! crate.
//!
//! The caller is also responsible for providing the random data used when
//! encoding the PIN field. This module does not generate randomness or assess
//! the entropy quality of the supplied random seed.
//!
//! Production use should employ a cryptographic provider and deployment model
//! appropriate for the applicable payment-security requirements.

use crate::utils::{left_pad_str, right_pad_str};
use crate::{Pin, PinBlockCryptoError, PinBlockError};

use paysec_crypto::AesBlockCipher;

use zeroize::Zeroizing;

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
/// * `pin` - ASCII-encoded PIN consisting of 4 to 12 decimal digits.
/// * `rnd_seed` - Random data used for the second half of the PIN field.
///   At least 8 bytes must be supplied.
///
/// # Returns
///
/// A 16-byte ISO 9564 format 4 PIN field.
///
/// # Errors
///
/// Returns [`PinBlockError::InvalidPin`] if `pin` does not contain between
/// 4 and 12 ASCII decimal digits.
///
/// Returns [`PinBlockError::RandomSeedTooShort`] if fewer than eight random
/// bytes are supplied.
///
/// # Security
///
/// This function accepts the PIN as a borrowed string and does not take
/// ownership of or zeroize the caller's input. The caller remains responsible
/// for the lifecycle of the supplied plaintext PIN.
pub fn encode_pin_field_iso_4(
    pin: &str,
    rnd_seed: Vec<u8>,
) -> Result<[u8; ISO4_PIN_BLOCK_LENGTH], PinBlockError> {
    if !(4..=12).contains(&pin.len()) || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(PinBlockError::InvalidPin);
    }

    if rnd_seed.len() < ISO4_RANDOM_SEED_LENGTH {
        return Err(PinBlockError::RandomSeedTooShort {
            minimum: ISO4_RANDOM_SEED_LENGTH,
            actual: rnd_seed.len(),
        });
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
/// The function validates the format identifier, encoded PIN length, PIN
/// digits, and filler nibbles before returning the decoded PIN.
///
/// # Parameters
///
/// * `pin_field` - Encoded ISO 9564 format 4 PIN field. It must be exactly
///   16 bytes long.
///
/// # Returns
///
/// The decoded plaintext PIN as a [`Pin`].
///
/// The returned `Pin` redacts its contents from debug output and zeroizes its
/// owned string when dropped. Call [`Pin::expose_secret`] when explicit access
/// to the plaintext PIN digits is required.
///
/// # Errors
///
/// Returns a [`PinBlockError`] if:
///
/// - the PIN field is not exactly 16 bytes long,
/// - the control field does not identify ISO format 4,
/// - the encoded PIN length is outside the range 4 to 12,
/// - an encoded PIN digit contains an invalid BCD value,
/// - a filler nibble is not `0xA`.
pub fn decode_pin_field_iso_4(pin_field: &[u8]) -> Result<Pin, PinBlockError> {
    if pin_field.len() != ISO4_PIN_BLOCK_LENGTH {
        return Err(PinBlockError::InvalidPinFieldLength {
            expected: ISO4_PIN_BLOCK_LENGTH,
            actual: pin_field.len(),
        });
    }

    // The high nibble identifies ISO format 4.
    let control_field = pin_field[0] >> 4;

    if control_field != 0x4 {
        return Err(PinBlockError::InvalidControlField {
            actual: control_field,
        });
    }

    // The low nibble contains the PIN length.
    let pin_len = (pin_field[0] & 0x0F) as usize;

    if !(4..=12).contains(&pin_len) {
        return Err(PinBlockError::InvalidDecodedPinLength { actual: pin_len });
    }

    // Validate all encoded PIN digits before constructing a plaintext String.
    for i in 0..pin_len {
        let digit = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if digit > 9 {
            return Err(PinBlockError::InvalidPinDigit);
        }
    }

    // All unused PIN-area nibbles must contain 0xA.
    for i in pin_len..14 {
        let filler = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        if filler != 0xA {
            return Err(PinBlockError::InvalidFiller);
        }
    }

    // The complete field has now been validated. Construct the plaintext PIN
    // only after all error-producing validation has succeeded.
    let mut pin = String::with_capacity(pin_len);

    for i in 0..pin_len {
        let digit = if i % 2 == 0 {
            pin_field[1 + i / 2] >> 4
        } else {
            pin_field[1 + i / 2] & 0x0F
        };

        pin.push(char::from(b'0' + digit));
    }

    // Move the plaintext String directly into the zeroizing Pin wrapper.
    Pin::new(pin)
}

/// Encode a Primary Account Number into an ISO 9564 format 4 PAN field.
///
/// The resulting PAN field is 16 bytes long and is used during format 4 PIN
/// block enciphering and deciphering.
///
/// # Parameters
///
/// * `pan` - ASCII-encoded PAN consisting of 1 to 19 decimal digits.
///
/// # Returns
///
/// A 16-byte ISO 9564 format 4 PAN field.
///
/// # Errors
///
/// Returns [`PinBlockError::InvalidPan`] if the PAN is empty, longer than
/// 19 digits, or contains a non-ASCII decimal digit.
///
/// Returns [`PinBlockError::Hex`] if hexadecimal decoding of the internally
/// constructed PAN field fails.
pub fn encode_pan_field_iso_4(pan: &str) -> Result<[u8; ISO4_PIN_BLOCK_LENGTH], PinBlockError> {
    if !(1..=19).contains(&pan.len()) || !pan.chars().all(|c| c.is_ascii_digit()) {
        return Err(PinBlockError::InvalidPan);
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

    let pan_field: [u8; ISO4_PIN_BLOCK_LENGTH] = pan_bytes
        .try_into()
        .map_err(|_| PinBlockError::InvalidPan)?;

    Ok(pan_field)
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
/// * `pin` - ASCII-encoded PIN consisting of 4 to 12 decimal digits.
/// * `pan` - ASCII-encoded PAN consisting of 1 to 19 decimal digits.
/// * `rnd_seed` - Random data used when encoding the PIN field. At least
///   8 bytes must be supplied.
///
/// # Returns
///
/// The encrypted 16-byte PIN block as a [`Vec<u8>`].
///
/// # Errors
///
/// Returns [`PinBlockCryptoError::PinBlock`] if PIN or PAN validation or
/// encoding fails.
///
/// Returns [`PinBlockCryptoError::Crypto`] if the cryptographic provider
/// reports an AES encryption error.
///
/// # Security
///
/// The plaintext PIN is borrowed from the caller and is not owned or zeroized
/// by this function. The internally encoded plaintext PIN field is zeroized
/// when it leaves scope.
///
/// Provider-managed AES keys retain the security properties of the selected
/// cryptographic provider.
pub fn encipher_pinblock_iso_4<P, K: ?Sized>(
    provider: &P,
    key: &K,
    pin: &str,
    pan: &str,
    rnd_seed: Vec<u8>,
) -> Result<Vec<u8>, PinBlockCryptoError<P::Error>>
where
    P: AesBlockCipher<K>,
{
    // Step 1: Encode PIN and PAN fields.
    //
    // The PIN field contains plaintext PIN-derived data, so keep it in a
    // zeroizing wrapper for the remainder of this operation.
    let pin_field = Zeroizing::new(encode_pin_field_iso_4(pin, rnd_seed)?);

    let pan_field = encode_pan_field_iso_4(pan)?;

    // Step 2: Encrypt the PIN field to produce intermediate block A.
    let intermediate_block_a = provider
        .encrypt_block(key, &*pin_field)
        .map_err(PinBlockCryptoError::Crypto)?;

    // Step 3: XOR intermediate block A with the PAN field to produce
    // intermediate block B.
    let intermediate_block_b: [u8; ISO4_PIN_BLOCK_LENGTH] =
        std::array::from_fn(|i| intermediate_block_a[i] ^ pan_field[i]);

    // Step 4: Encrypt intermediate block B.
    let encrypted_block = provider
        .encrypt_block(key, &intermediate_block_b)
        .map_err(PinBlockCryptoError::Crypto)?;

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
/// The deciphered plaintext PIN as a [`Pin`].
///
/// The returned `Pin` redacts its plaintext digits from debug output and
/// zeroizes its owned string when dropped. Call [`Pin::expose_secret`] when
/// explicit access to the PIN digits is required.
///
/// # Errors
///
/// Returns [`PinBlockCryptoError::PinBlock`] if:
///
/// - the encrypted PIN block is not exactly 16 bytes long,
/// - PAN processing fails,
/// - the recovered plaintext PIN field is malformed.
///
/// Returns [`PinBlockCryptoError::Crypto`] if the cryptographic provider
/// reports an AES decryption error.
///
/// # Security
///
/// The recovered plaintext PIN field is zeroized when it leaves scope, and
/// the decoded PIN is returned in a [`Pin`] wrapper that zeroizes its owned
/// plaintext representation when dropped.
///
/// Provider-managed AES keys retain the security properties of the selected
/// cryptographic provider.
pub fn decipher_pinblock_iso_4<P, K: ?Sized>(
    provider: &P,
    key: &K,
    pin_block: &[u8],
    pan: &str,
) -> Result<Pin, PinBlockCryptoError<P::Error>>
where
    P: AesBlockCipher<K>,
{
    let pin_block: &[u8; ISO4_PIN_BLOCK_LENGTH] =
        pin_block
            .try_into()
            .map_err(|_| PinBlockError::InvalidPinBlockLength {
                expected: ISO4_PIN_BLOCK_LENGTH,
                actual: pin_block.len(),
            })?;

    // Step 1: Decrypt the PIN block to obtain intermediate block B.
    let intermediate_block_b = provider
        .decrypt_block(key, pin_block)
        .map_err(PinBlockCryptoError::Crypto)?;

    // Step 2: Encode the PAN field.
    let pan_field = encode_pan_field_iso_4(pan)?;

    // Step 3: XOR intermediate block B with the PAN field to recover
    // intermediate block A.
    let intermediate_block_a: [u8; ISO4_PIN_BLOCK_LENGTH] =
        std::array::from_fn(|i| intermediate_block_b[i] ^ pan_field[i]);

    // Step 4: Decrypt intermediate block A to recover the plaintext PIN field.
    //
    // The recovered field contains plaintext PIN-derived data, so zeroize it
    // when it leaves scope.
    let pin_field = Zeroizing::new(
        provider
            .decrypt_block(key, &intermediate_block_a)
            .map_err(PinBlockCryptoError::Crypto)?,
    );

    // Step 5: Decode the plaintext PIN field into a zeroizing Pin.
    decode_pin_field_iso_4(&*pin_field).map_err(PinBlockCryptoError::PinBlock)
}
