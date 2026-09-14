use paysec_crypto::{AesBlockCipher, AesKeySize};

use zeroize::Zeroizing;

use crate::{DukptError, DukptKey, InitialKeyId};

const DERIVATION_DATA_VERSION: u8 = 0x01;

const INITIAL_KEY_USAGE: u16 = 0x8001;

/// Create the ANSI X9.24-3 derivation data used for Initial Key derivation.
///
/// The resulting derivation data is exactly one AES block:
///
/// ```text
/// byte 0      Version
/// byte 1      Key Block Counter
/// bytes 2-3   Key Usage Indicator
/// bytes 4-5   Algorithm Indicator
/// bytes 6-7   Key Length in bits
/// bytes 8-15  Initial Key ID
/// ```
fn create_initial_key_derivation_data(
    key_size: AesKeySize,
    initial_key_id: InitialKeyId,
) -> [u8; 16] {
    let (algorithm_indicator, key_length_bits) = match key_size {
        AesKeySize::Bits128 => (0x0002u16, 0x0080u16),
        AesKeySize::Bits192 => (0x0003u16, 0x00C0u16),
        AesKeySize::Bits256 => (0x0004u16, 0x0100u16),
    };

    let mut derivation_data = [0u8; 16];

    derivation_data[0] = DERIVATION_DATA_VERSION;

    // Derive_Key updates this field for every generated output block.
    // The first block always starts at one.
    derivation_data[1] = 0x01;

    derivation_data[2..4].copy_from_slice(&INITIAL_KEY_USAGE.to_be_bytes());

    derivation_data[4..6].copy_from_slice(&algorithm_indicator.to_be_bytes());

    derivation_data[6..8].copy_from_slice(&key_length_bits.to_be_bytes());

    derivation_data[8..16].copy_from_slice(initial_key_id.as_bytes());

    derivation_data
}

/// Derive a key using the ANSI X9.24-3 AES DUKPT derivation function.
///
/// The derivation-data block counter is updated for each 16-byte block of
/// generated key material. AES-192 and AES-256 therefore require two AES
/// block operations.
///
/// This function is intentionally kept private to the DUKPT implementation.
/// Cryptographic AES block operations are delegated to the supplied provider.
fn derive_key<P, K: ?Sized>(
    provider: &P,
    key: &K,
    output_key_size: AesKeySize,
    derivation_data: &[u8; 16],
) -> Result<DukptKey, DukptError<P::Error>>
where
    P: AesBlockCipher<K>,
{
    let output_len = output_key_size.bytes();

    let block_count = output_len.div_ceil(16);

    let mut derived_key = Zeroizing::new(Vec::with_capacity(output_len));

    let mut derivation_block = *derivation_data;

    for block_counter in 1..=block_count {
        derivation_block[1] =
            u8::try_from(block_counter).expect("AES DUKPT requires at most two derivation blocks");

        let encrypted_block = Zeroizing::new(
            provider
                .encrypt_block(key, &derivation_block)
                .map_err(DukptError::Crypto)?,
        );

        let remaining = output_len - derived_key.len();

        let bytes_to_copy = remaining.min(encrypted_block.len());

        derived_key.extend_from_slice(&encrypted_block[..bytes_to_copy]);
    }

    Ok(DukptKey::from_zeroizing(derived_key))
}

/// Derives an AES DUKPT Initial Key from a Base Derivation Key.
///
/// The Initial Key has the same AES key size as the BDK.
///
/// Cryptographic operations are delegated to the supplied AES provider.
///
/// # Parameters
///
/// * `provider` - Provider used for AES block encryption.
/// * `bdk` - Provider-specific Base Derivation Key.
/// * `bdk_size` - AES size of the BDK and resulting Initial Key.
/// * `initial_key_id` - 64-bit Initial Key ID.
///
/// # Returns
///
/// The derived Initial Key wrapped in [`DukptKey`].
///
/// The returned value redacts its key bytes from debug output and zeroizes
/// its owned memory when dropped.
///
/// # Errors
///
/// Returns [`DukptError::Crypto`] if the cryptographic provider fails while
/// performing AES block encryption.
pub fn derive_initial_key<P, K: ?Sized>(
    provider: &P,
    bdk: &K,
    bdk_size: AesKeySize,
    initial_key_id: InitialKeyId,
) -> Result<DukptKey, DukptError<P::Error>>
where
    P: AesBlockCipher<K>,
{
    let derivation_data = create_initial_key_derivation_data(bdk_size, initial_key_id);

    derive_key(provider, bdk, bdk_size, &derivation_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_key_derivation_data_aes_128() {
        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let derivation_data =
            create_initial_key_derivation_data(AesKeySize::Bits128, initial_key_id);

        assert_eq!(
            hex::encode_upper(derivation_data),
            "01018001000200801234567890123456",
        );
    }

    #[test]
    fn test_initial_key_derivation_data_aes_192() {
        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let derivation_data =
            create_initial_key_derivation_data(AesKeySize::Bits192, initial_key_id);

        assert_eq!(
            hex::encode_upper(derivation_data),
            "01018001000300C01234567890123456",
        );
    }

    #[test]
    fn test_initial_key_derivation_data_aes_256() {
        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let derivation_data =
            create_initial_key_derivation_data(AesKeySize::Bits256, initial_key_id);

        assert_eq!(
            hex::encode_upper(derivation_data),
            "01018001000401001234567890123456",
        );
    }
}
