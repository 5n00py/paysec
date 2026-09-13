use super::error::PayloadError;

/// Maximum key length that can be represented by the TR-31 two-byte
/// key-length-in-bits field.
const MAX_KEY_LENGTH_BYTES: usize = u16::MAX as usize / 8;

/// Construct the payload for a TR-31 key block.
///
/// The payload consists of:
///
/// 1. A two-byte big-endian key length expressed in bits.
/// 2. The key or sensitive data.
/// 3. Random padding sufficient to align the payload to the cipher block
///    length and, if requested, mask the actual key length.
///
/// # Parameters
///
/// * `key` - The key or sensitive data being protected.
/// * `masked_key_length` - Minimum key-data length to expose through the
///   resulting payload size. A value shorter than the actual key length has
///   no effect.
/// * `cipher_block_length` - Block length of the encryption cipher.
/// * `random_seed` - Random bytes used as payload padding.
///
/// # Returns
///
/// The constructed plaintext TR-31 payload.
///
/// # Errors
///
/// Returns [`PayloadError::KeyTooLong`] if the key length cannot be represented
/// in the TR-31 two-byte key-length field.
///
/// Returns [`PayloadError::InvalidCipherBlockLength`] if
/// `cipher_block_length` is zero.
///
/// Returns [`PayloadError::RandomSeedTooShort`] if the supplied random seed
/// does not contain enough bytes for the required padding.
///
/// Returns [`PayloadError::InvalidTotalPayloadLength`] if calculating the
/// payload size overflows or otherwise produces an invalid result.
pub fn construct_payload(
    key: &[u8],
    masked_key_length: usize,
    cipher_block_length: usize,
    random_seed: &[u8],
) -> Result<Vec<u8>, PayloadError> {
    let key_len = key.len();

    let key_length_bits = key_len
        .checked_mul(8)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(PayloadError::KeyTooLong {
            max: MAX_KEY_LENGTH_BYTES,
            actual: key_len,
        })?;

    let padding_length = calculate_padding_length(key_len, masked_key_length, cipher_block_length)?;

    let payload_capacity = key_len
        .checked_add(2)
        .and_then(|value| value.checked_add(padding_length))
        .ok_or(PayloadError::InvalidTotalPayloadLength)?;

    let mut payload = Vec::with_capacity(payload_capacity);

    // Key length is stored in bits as a 16-bit big-endian integer.
    payload.extend_from_slice(&key_length_bits.to_be_bytes());

    // Append the actual protected key or sensitive data.
    payload.extend_from_slice(key);

    if random_seed.len() < padding_length {
        return Err(PayloadError::RandomSeedTooShort {
            required: padding_length,
            actual: random_seed.len(),
        });
    }

    // Only the amount of random data required for padding is consumed.
    payload.extend_from_slice(&random_seed[..padding_length]);

    Ok(payload)
}

/// Extract the protected key from a TR-31 plaintext payload.
///
/// The first two bytes of the payload contain the key length in bits. The
/// corresponding number of key bytes immediately follows.
///
/// Any remaining data is payload padding and is ignored by this function.
///
/// # Parameters
///
/// * `payload` - Plaintext TR-31 payload.
///
/// # Returns
///
/// The extracted key or sensitive data.
///
/// # Errors
///
/// Returns [`PayloadError::PayloadTooShort`] if the payload does not contain
/// the two-byte key-length field.
///
/// Returns [`PayloadError::PayloadTooShortForKey`] if the payload does not
/// contain enough bytes for the declared key length.
pub fn extract_key_from_payload(payload: &[u8]) -> Result<Vec<u8>, PayloadError> {
    const KEY_LENGTH_FIELD_SIZE: usize = 2;

    if payload.len() < KEY_LENGTH_FIELD_SIZE {
        return Err(PayloadError::PayloadTooShort {
            minimum: KEY_LENGTH_FIELD_SIZE,
            actual: payload.len(),
        });
    }

    let key_length_bits = u16::from_be_bytes([payload[0], payload[1]]);

    let key_length_bytes = (key_length_bits / 8) as usize;

    let required_length = KEY_LENGTH_FIELD_SIZE
        .checked_add(key_length_bytes)
        .ok_or(PayloadError::InvalidTotalPayloadLength)?;

    if payload.len() < required_length {
        return Err(PayloadError::PayloadTooShortForKey {
            required: required_length,
            actual: payload.len(),
        });
    }

    Ok(payload[KEY_LENGTH_FIELD_SIZE..required_length].to_vec())
}

/// Calculate the padding length required for a TR-31 payload.
///
/// The plaintext payload consists of a two-byte key-length field, the key, and
/// padding. Its final size is rounded up to a multiple of
/// `cipher_block_length`.
///
/// `masked_key_length` can be used to make a shorter key occupy the same
/// payload size as a longer key.
///
/// # Parameters
///
/// * `key_len` - Actual key length in bytes.
/// * `masked_key_length` - Minimum key-data length represented by the payload.
/// * `cipher_block_length` - Cipher block length in bytes.
///
/// # Returns
///
/// Number of padding bytes required.
///
/// # Errors
///
/// Returns [`PayloadError::InvalidCipherBlockLength`] if the cipher block
/// length is zero.
///
/// Returns [`PayloadError::InvalidTotalPayloadLength`] if calculating the
/// required payload size overflows or produces an invalid length.
pub fn calculate_padding_length(
    key_len: usize,
    masked_key_length: usize,
    cipher_block_length: usize,
) -> Result<usize, PayloadError> {
    if cipher_block_length == 0 {
        return Err(PayloadError::InvalidCipherBlockLength);
    }

    let raw_key_section_length = 2usize
        .checked_add(key_len)
        .ok_or(PayloadError::InvalidTotalPayloadLength)?;

    let effective_key_length = std::cmp::max(key_len, masked_key_length);

    // Round 2 + effective_key_length up to the next cipher-block boundary.
    //
    // Equivalent to:
    //
    // ((length + block_size - 1) / block_size) * block_size
    //
    // but using checked arithmetic so malformed/extreme input cannot cause
    // an integer-overflow panic.
    let length_to_round = 2usize
        .checked_add(effective_key_length)
        .and_then(|value| value.checked_add(cipher_block_length - 1))
        .ok_or(PayloadError::InvalidTotalPayloadLength)?;

    let block_count = length_to_round / cipher_block_length;

    let total_payload_length = block_count
        .checked_mul(cipher_block_length)
        .ok_or(PayloadError::InvalidTotalPayloadLength)?;

    if total_payload_length < raw_key_section_length {
        return Err(PayloadError::InvalidTotalPayloadLength);
    }

    Ok(total_payload_length - raw_key_section_length)
}

#[test]
fn test_calculate_padding_length_zero_block_length() {
    let result = calculate_padding_length(16, 0, 0);

    assert_eq!(result, Err(PayloadError::InvalidCipherBlockLength));
}

#[test]
fn test_construct_payload_random_seed_too_short() {
    let key = [0u8; 16];

    let result = construct_payload(&key, 0, 16, &[]);

    assert!(matches!(
        result,
        Err(PayloadError::RandomSeedTooShort {
            required,
            actual: 0,
        }) if required > 0
    ));
}
