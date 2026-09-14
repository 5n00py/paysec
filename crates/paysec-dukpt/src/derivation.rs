use paysec_crypto::{AesBlockCipher, AesKeySize};

use zeroize::Zeroizing;

use crate::{DukptError, DukptKey, InitialKeyId, WorkingKeyUsage};

const AES_BLOCK_SIZE: usize = 16;

const DERIVATION_DATA_VERSION: u8 = 0x01;
const FIRST_DERIVATION_BLOCK: u8 = 0x01;

const KEY_USAGE_KEY_DERIVATION: u16 = 0x8000;
const KEY_USAGE_INITIAL_KEY_DERIVATION: u16 = 0x8001;

const TRANSACTION_COUNTER_MSB: u32 = 0x8000_0000;

/// Returns the ANSI X9.24-3 algorithm indicator and key length in bits for
/// the requested AES key size.
fn aes_key_parameters(key_size: AesKeySize) -> (u16, u16) {
    match key_size {
        AesKeySize::Bits128 => (0x0002, 0x0080),
        AesKeySize::Bits192 => (0x0003, 0x00C0),
        AesKeySize::Bits256 => (0x0004, 0x0100),
    }
}

/// Creates the common first eight bytes of an ANSI X9.24-3 derivation-data
/// block.
///
/// Bytes 8 through 15 depend on the purpose of the derivation and are filled
/// by the caller.
fn create_derivation_data_base(key_usage: u16, key_size: AesKeySize) -> [u8; 16] {
    let (algorithm_indicator, key_length_bits) = aes_key_parameters(key_size);

    let mut derivation_data = [0u8; AES_BLOCK_SIZE];

    derivation_data[0] = DERIVATION_DATA_VERSION;

    // Derive_Key replaces this value for every generated output block.
    derivation_data[1] = FIRST_DERIVATION_BLOCK;

    derivation_data[2..4].copy_from_slice(&key_usage.to_be_bytes());

    derivation_data[4..6].copy_from_slice(&algorithm_indicator.to_be_bytes());

    derivation_data[6..8].copy_from_slice(&key_length_bits.to_be_bytes());

    derivation_data
}

/// Creates the ANSI X9.24-3 derivation data used to derive an Initial Key.
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
    let mut derivation_data =
        create_derivation_data_base(KEY_USAGE_INITIAL_KEY_DERIVATION, key_size);

    derivation_data[8..16].copy_from_slice(initial_key_id.as_bytes());

    derivation_data
}

/// Creates ANSI X9.24-3 derivation data for keys derived after the Initial
/// Key.
///
/// This format is used both while walking the intermediate derivation-key
/// tree and when deriving the final working key.
///
/// The key usage and requested output-key size determine bytes 2 through 7.
/// Bytes 8 through 15 identify the derivation path:
///
/// ```text
/// byte 0       Version
/// byte 1       Key Block Counter
/// bytes 2-3    Key Usage Indicator
/// bytes 4-5    Algorithm Indicator
/// bytes 6-7    Key Length in bits
/// bytes 8-11   Derivation ID
/// bytes 12-15  Transaction Counter
/// ```
///
/// The Derivation ID is the rightmost 32 bits of the Initial Key ID.
fn create_other_key_derivation_data(
    key_usage: u16,
    key_size: AesKeySize,
    initial_key_id: InitialKeyId,
    transaction_counter: u32,
) -> [u8; 16] {
    let mut derivation_data = create_derivation_data_base(key_usage, key_size);

    derivation_data[8..12].copy_from_slice(&initial_key_id.as_bytes()[4..8]);

    derivation_data[12..16].copy_from_slice(&transaction_counter.to_be_bytes());

    derivation_data
}

/// Derives key material using the ANSI X9.24-3 AES DUKPT derivation
/// function.
///
/// Each output block is produced by incrementing the derivation-data Key
/// Block Counter and encrypting the resulting 16-byte block with AES.
///
/// AES-128 requires one block. AES-192 and AES-256 require two blocks, with
/// AES-192 using only the first eight bytes of the second block.
///
/// This is an internal DUKPT primitive. AES encryption itself is delegated
/// to the supplied cryptographic provider.
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

    let block_count = output_len.div_ceil(AES_BLOCK_SIZE);

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

/// Reconstructs the current intermediate derivation key for a transaction
/// counter.
///
/// ANSI X9.24-3 organizes intermediate derivation keys as a tree. A key for
/// a counter value is derived from the key corresponding to that counter
/// with its rightmost set bit removed.
///
/// The host therefore walks the transaction counter from the most-significant
/// bit to the least-significant bit. Each set bit advances one level through
/// the derivation tree.
///
/// For example, counter `0b1011` follows:
///
/// ```text
/// Initial Key
///     |
///     | 1000
///     v
/// Key 1000
///     |
///     | 1010
///     v
/// Key 1010
///     |
///     | 1011
///     v
/// Key 1011
/// ```
///
/// Only set bits require a derivation operation; the host does not need to
/// derive all preceding transaction keys.
fn derive_intermediate_key<P>(
    provider: &P,
    mut derivation_key: DukptKey,
    derivation_key_size: AesKeySize,
    initial_key_id: InitialKeyId,
    transaction_counter: u32,
) -> Result<DukptKey, DukptError<P::Error>>
where
    P: AesBlockCipher<[u8]>,
{
    let mut working_counter = 0u32;

    // Walk the transaction counter from its most-significant bit toward its
    // least-significant bit. Each set bit identifies the next node on the
    // derivation path.
    //
    // For counter 0x00000003 (...0011):
    //
    //     0 -> 2 -> 3
    //
    // The host therefore derives the key for counter 2 first and then uses
    // that key to derive the key for counter 3. Unset bits require no
    // derivation operation.
    let mut mask = TRANSACTION_COUNTER_MSB;

    while mask != 0 {
        if transaction_counter & mask != 0 {
            working_counter |= mask;

            let derivation_data = create_other_key_derivation_data(
                KEY_USAGE_KEY_DERIVATION,
                derivation_key_size,
                initial_key_id,
                working_counter,
            );

            derivation_key = derive_key(
                provider,
                derivation_key.expose_secret(),
                derivation_key_size,
                &derivation_data,
            )?;
        }

        mask >>= 1;
    }

    Ok(derivation_key)
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

fn working_key_size_is_allowed(
    derivation_key_size: AesKeySize,
    working_key_size: AesKeySize,
) -> bool {
    match derivation_key_size {
        AesKeySize::Bits128 => {
            matches!(working_key_size, AesKeySize::Bits128)
        }

        AesKeySize::Bits192 => {
            matches!(working_key_size, AesKeySize::Bits128 | AesKeySize::Bits192)
        }

        AesKeySize::Bits256 => true,
    }
}

fn derive_working_key_from_intermediate<P>(
    provider: &P,
    intermediate_key: &DukptKey,
    working_key_usage: WorkingKeyUsage,
    working_key_size: AesKeySize,
    initial_key_id: InitialKeyId,
    transaction_counter: u32,
) -> Result<DukptKey, DukptError<P::Error>>
where
    P: AesBlockCipher<[u8]>,
{
    let derivation_data = create_other_key_derivation_data(
        working_key_usage.indicator(),
        working_key_size,
        initial_key_id,
        transaction_counter,
    );

    derive_key(
        provider,
        intermediate_key.expose_secret(),
        working_key_size,
        &derivation_data,
    )
}

/// Derives an AES DUKPT working key on the receiving / host side.
///
/// The function reconstructs the transaction key hierarchy from the BDK:
///
/// ```text
/// BDK
///  |
///  v
/// Initial Key
///  |
///  v
/// Intermediate Derivation Key
///  |
///  v
/// Working Key
/// ```
///
/// The transaction counter determines the path through the intermediate
/// derivation-key tree. The working-key usage is included in the final
/// derivation data so that keys intended for different purposes are
/// cryptographically separated.
///
/// The BDK, Initial Key, and intermediate derivation keys all use
/// `derivation_key_size`. The final working key may use the same AES size
/// or a weaker one, but never a stronger one.
///
/// # Parameters
///
/// * `provider` - Provider used for AES block encryption.
/// * `bdk` - Provider-specific Base Derivation Key.
/// * `derivation_key_size` - AES size of the BDK, Initial Key, and
///   intermediate derivation keys.
/// * `working_key_usage` - Intended purpose of the resulting working key.
/// * `working_key_size` - AES size of the resulting working key.
/// * `initial_key_id` - 64-bit Initial Key ID.
/// * `transaction_counter` - 32-bit transaction counter.
///
/// # Returns
///
/// The transaction working key wrapped in [`DukptKey`].
///
/// # Errors
///
/// Returns [`DukptError::WorkingKeyTooStrong`] if `working_key_size` is
/// stronger than `derivation_key_size`.
///
/// Returns [`DukptError::Crypto`] if the cryptographic provider fails while
/// performing an AES operation.
pub fn derive_working_key<P, K: ?Sized>(
    provider: &P,
    bdk: &K,
    derivation_key_size: AesKeySize,
    working_key_usage: WorkingKeyUsage,
    working_key_size: AesKeySize,
    initial_key_id: InitialKeyId,
    transaction_counter: u32,
) -> Result<DukptKey, DukptError<P::Error>>
where
    P: AesBlockCipher<K> + AesBlockCipher<[u8]>,
{
    if !working_key_size_is_allowed(derivation_key_size, working_key_size) {
        return Err(DukptError::WorkingKeyTooStrong {
            derivation_key_size,
            working_key_size,
        });
    }

    let initial_key = derive_initial_key(provider, bdk, derivation_key_size, initial_key_id)?;

    let intermediate_key = derive_intermediate_key(
        provider,
        initial_key,
        derivation_key_size,
        initial_key_id,
        transaction_counter,
    )?;

    derive_working_key_from_intermediate(
        provider,
        &intermediate_key,
        working_key_usage,
        working_key_size,
        initial_key_id,
        transaction_counter,
    )
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

    #[test]
    fn test_intermediate_key_derivation_data_counter_1() {
        let initial_key_id =
            InitialKeyId::new(hex::decode("0123456789ABCDEF").unwrap().try_into().unwrap());

        let derivation_data = create_other_key_derivation_data(
            KEY_USAGE_KEY_DERIVATION,
            AesKeySize::Bits128,
            initial_key_id,
            0x0000_0001,
        );

        assert_eq!(
            hex::encode_upper(derivation_data),
            "010180000002008089ABCDEF00000001",
        );
    }

    #[test]
    fn test_intermediate_key_derivation_data_counter_1200() {
        let initial_key_id =
            InitialKeyId::new(hex::decode("0123456789ABCDEF").unwrap().try_into().unwrap());

        let derivation_data = create_other_key_derivation_data(
            KEY_USAGE_KEY_DERIVATION,
            AesKeySize::Bits128,
            initial_key_id,
            0x0000_1200,
        );

        assert_eq!(
            hex::encode_upper(derivation_data),
            "010180000002008089ABCDEF00001200",
        );
    }
    #[test]
    fn test_working_key_derivation_data_mac_generation_aes_128() {
        let initial_key_id = InitialKeyId::from_parts(0x12345678, 0x90123456);

        let derivation_data = create_other_key_derivation_data(
            WorkingKeyUsage::MessageAuthenticationGeneration.indicator(),
            AesKeySize::Bits128,
            initial_key_id,
            0x0000_0001,
        );

        assert_eq!(
            hex::encode_upper(derivation_data,),
            "01012000000200809012345600000001",
        );
    }

    #[test]
    fn test_working_key_size_validation() {
        assert!(working_key_size_is_allowed(
            AesKeySize::Bits128,
            AesKeySize::Bits128,
        ));

        assert!(!working_key_size_is_allowed(
            AesKeySize::Bits128,
            AesKeySize::Bits192,
        ));

        assert!(!working_key_size_is_allowed(
            AesKeySize::Bits128,
            AesKeySize::Bits256,
        ));

        assert!(working_key_size_is_allowed(
            AesKeySize::Bits192,
            AesKeySize::Bits128,
        ));

        assert!(working_key_size_is_allowed(
            AesKeySize::Bits192,
            AesKeySize::Bits192,
        ));

        assert!(!working_key_size_is_allowed(
            AesKeySize::Bits192,
            AesKeySize::Bits256,
        ));

        assert!(working_key_size_is_allowed(
            AesKeySize::Bits256,
            AesKeySize::Bits128,
        ));

        assert!(working_key_size_is_allowed(
            AesKeySize::Bits256,
            AesKeySize::Bits192,
        ));

        assert!(working_key_size_is_allowed(
            AesKeySize::Bits256,
            AesKeySize::Bits256,
        ));
    }
}
