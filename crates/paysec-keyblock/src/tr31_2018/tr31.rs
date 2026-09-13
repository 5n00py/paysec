//! TR-31 key block wrapping and unwrapping.
//!
//! This module implements TR-31 key block version `D` according to
//! ASC X9 TR 31-2018.
//!
//! Version `D` uses AES for key-block protection. The Key Block Protection Key
//! (KBPK) is used to derive:
//!
//! - the Key Block Encryption Key (KBEK), and
//! - the Key Block Authentication Key (KBAK).
//!
//! The KBEK is used for AES-CBC encryption and decryption of the confidential
//! payload. The KBAK is used to calculate an AES-CMAC over the header and
//! plaintext payload.
//!
//! Cryptographic operations are delegated to a provider implementing the
//! required interfaces from `paysec-crypto`. This allows the TR-31
//! implementation to remain independent from any particular AES library and
//! permits providers to represent KBPK, KBEK, and KBAK using either software
//! key material or opaque key handles.
//!
//! # Key Block Format
//!
//! A TR-31 key block consists of:
//!
//! 1. A clear-text key block header.
//! 2. An encrypted confidential payload containing the protected key.
//! 3. A 16-byte message authentication code.
//!
//! # Supported Version
//!
//! Only TR-31 version `D` is currently supported.
//!
//! # Error Handling
//!
//! TR-31 formatting, parsing, validation, and authentication failures are
//! reported through [`crate::Tr31Error`].
//!
//! Errors returned by the selected cryptographic provider, including key
//! derivation, AES-CMAC, and AES-CBC failures, are preserved through
//! [`crate::Tr31CryptoError::Crypto`].
//!
//! # Random Padding
//!
//! Random data used for payload padding must be supplied by the caller. This
//! crate does not generate randomness or assess its entropy quality.
//!
//! # Security
//!
//! The cryptographic security properties of wrapping and unwrapping depend on
//! the selected crypto provider. Production environments should use a provider
//! appropriate for their security requirements, such as an HSM-backed provider
//! where required.
//!
//! Plaintext key material returned by unwrapping is held in [`crate::SecretKey`].
//! The wrapper redacts debug output and zeroizes its owned bytes when dropped.
//! Temporary plaintext payload buffers created internally during wrapping and
//! unwrapping are also zeroized when they leave scope.
//!
//! These measures provide defense in depth against accidental disclosure and
//! residual process-memory contents. They do not replace the stronger
//! protection provided by an HSM or guarantee that callers have not retained
//! additional copies of plaintext key material.
//!
//! # Example
//!
//! ```
//! use paysec_crypto::AesKeySize;
//! use paysec_crypto_soft_aes::SoftAesProvider;
//! use paysec_keyblock::{
//!     tr31_unwrap,
//!     tr31_wrap,
//!     KeyBlockHeader,
//! };
//!
//! let provider = SoftAesProvider::new();
//!
//! let header = KeyBlockHeader::new_with_values(
//!     "D",
//!     "P0",
//!     "A",
//!     "E",
//!     "00",
//!     "E",
//! )
//! .unwrap();
//!
//! let key =
//!     hex::decode("3F419E1CB7079442AA37474C2EFBF8B8")
//!         .unwrap();
//!
//! let random_seed =
//!     hex::decode("1C2965473CE206BB855B01533782")
//!         .unwrap();
//!
//! let kbpk = hex::decode(
//!     "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6",
//! )
//! .unwrap();
//!
//! let key_block = tr31_wrap(
//!     &provider,
//!     kbpk.as_slice(),
//!     AesKeySize::Bits256,
//!     header,
//!     &key,
//!     0,
//!     &random_seed,
//! )
//! .unwrap();
//!
//! let expected =
//!     "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";
//!
//! assert_eq!(key_block, expected);
//!
//! let (_, unwrapped_key) = tr31_unwrap(
//!     &provider,
//!     kbpk.as_slice(),
//!     AesKeySize::Bits256,
//!     &key_block,
//! )
//! .unwrap();
//!
//! assert_eq!(unwrapped_key.expose_secret(), key.as_slice());
//! ```

use super::error::{Tr31CryptoError, Tr31Error};
use super::key_block_header::KeyBlockHeader;
use super::key_derivations::derive_keys_version_d;
use super::payload::{construct_payload, extract_key_from_payload};

use crate::SecretKey;
use zeroize::Zeroizing;

use paysec_crypto::{AesCbc, AesCmac, AesCmacKeyDerivation, AesKeySize};

const TR31_D_MAC_LEN: usize = 16;
const TR31_D_BLOCK_LEN: usize = 16;

/// Wrap a cryptographic key according to TR-31 key block version `D`.
///
/// The KBPK is provider-specific. The provider derives KBEK and KBAK from
/// the KBPK, calculates the authentication code using KBAK, and encrypts the
/// confidential payload using KBEK.
///
/// # Parameters
///
/// * `provider` - Cryptographic provider used for key derivation, AES-CMAC,
///   and AES-CBC encryption.
/// * `kbpk` - Provider-specific Key Block Protection Key.
/// * `kbpk_size` - AES key size of the KBPK and derived keys.
/// * `header` - Key block header. Its key-block length field is updated by
///   this function.
/// * `key` - Cryptographic key or sensitive data to protect.
/// * `masked_key_len` - Optional masked key length. A value of zero, or a
///   value smaller than the actual key length, disables masking.
/// * `random_seed` - Random data used for payload padding.
///
/// # Returns
///
/// The complete ASCII-encoded TR-31 key block.
///
/// # Errors
///
/// Returns [`Tr31CryptoError::Tr31`] if:
///
/// - the header does not specify version `D`,
/// - payload construction fails,
/// - the resulting key block length is invalid,
/// - header processing fails.
///
/// Returns [`Tr31CryptoError::Crypto`] if the cryptographic provider reports
/// a key-derivation, AES-CMAC, or AES-CBC encryption error.
pub fn tr31_wrap<P, K: ?Sized>(
    provider: &P,
    kbpk: &K,
    kbpk_size: AesKeySize,
    mut header: KeyBlockHeader,
    key: &[u8],
    masked_key_len: usize,
    random_seed: &[u8],
) -> Result<String, Tr31CryptoError<P::Error>>
where
    P: AesCmacKeyDerivation<K>
        + AesCbc<<P as AesCmacKeyDerivation<K>>::DerivedKey>
        + AesCmac<<P as AesCmacKeyDerivation<K>>::DerivedKey>,
{
    if header.version_id() != "D" {
        return Err(Tr31Error::UnsupportedVersion(header.version_id().to_string()).into());
    }

    // Derive KBEK and KBAK from the KBPK.
    let (kbek, kbak) =
        derive_keys_version_d(provider, kbpk, kbpk_size).map_err(Tr31CryptoError::Crypto)?;

    // Construct the confidential payload.
    let payload = Zeroizing::new(construct_payload(
        key,
        masked_key_len,
        TR31_D_BLOCK_LEN,
        random_seed,
    )?);

    // The serialized encrypted payload and MAC are represented as hexadecimal,
    // so each binary byte consumes two ASCII characters.
    let total_block_length = header.len() + (payload.len() * 2) + (TR31_D_MAC_LEN * 2);

    if total_block_length % TR31_D_BLOCK_LEN != 0 {
        return Err(Tr31Error::TotalBlockLengthNotMultiple {
            block_length: TR31_D_BLOCK_LEN,
            actual: total_block_length,
        }
        .into());
    }

    // Update the key block length before authenticating the header.
    header.set_kb_length(total_block_length as u16)?;

    let header_str = header.export_str()?;

    // MAC input is the clear-text header followed by the plaintext payload.
    let mut mac_input = Zeroizing::new(header_str.as_bytes().to_vec());

    mac_input.extend_from_slice(payload.as_slice());

    // Authenticate with KBAK.
    let mac = provider
        .calculate_cmac(&kbak, mac_input.as_slice())
        .map_err(Tr31CryptoError::Crypto)?;

    // For TR-31 version D, the MAC is also used as the CBC IV.
    let iv = mac;

    // Encrypt the confidential payload with KBEK.
    let encrypted_payload = provider
        .encrypt_cbc(&kbek, &iv, payload.as_slice())
        .map_err(Tr31CryptoError::Crypto)?;

    let encrypted_payload_hex = hex::encode_upper(&encrypted_payload);

    let mac_hex = hex::encode_upper(mac);

    Ok(format!("{header_str}{encrypted_payload_hex}{mac_hex}"))
}

/// Wrap a cryptographic key according to TR-31 version `D` using a header
/// supplied as a string.
///
/// This is a convenience wrapper around [`tr31_wrap`]. The supplied header is
/// first parsed into a [`KeyBlockHeader`] and then passed to the normal
/// wrapping operation.
///
/// # Parameters
///
/// * `provider` - Cryptographic provider.
/// * `kbpk` - Provider-specific Key Block Protection Key.
/// * `kbpk_size` - AES size of the KBPK.
/// * `header_str` - String representation of the TR-31 header.
/// * `key` - Cryptographic key or sensitive data to protect.
/// * `masked_key_len` - Optional masked key length.
/// * `random_seed` - Random data used for payload padding.
///
/// # Returns
///
/// The complete ASCII-encoded TR-31 key block.
///
/// # Errors
///
/// Returns [`Tr31CryptoError::Tr31`] if the header cannot be parsed or if any
/// TR-31 wrapping, payload, or header operation fails.
///
/// Returns [`Tr31CryptoError::Crypto`] if the cryptographic provider reports
/// a key-derivation, AES-CMAC, or AES-CBC encryption error.
pub fn tr31_wrap_with_header_string<P, K: ?Sized>(
    provider: &P,
    kbpk: &K,
    kbpk_size: AesKeySize,
    header_str: &str,
    key: &[u8],
    masked_key_len: usize,
    random_seed: &[u8],
) -> Result<String, Tr31CryptoError<P::Error>>
where
    P: AesCmacKeyDerivation<K>
        + AesCbc<<P as AesCmacKeyDerivation<K>>::DerivedKey>
        + AesCmac<<P as AesCmacKeyDerivation<K>>::DerivedKey>,
{
    let header = KeyBlockHeader::new_from_str(header_str)?;

    tr31_wrap(
        provider,
        kbpk,
        kbpk_size,
        header,
        key,
        masked_key_len,
        random_seed,
    )
}

/// Unwrap a cryptographic key from a TR-31 key block version `D`.
///
/// The provider derives KBEK and KBAK from the supplied KBPK. KBEK is used to
/// decrypt the confidential payload and KBAK is used to verify the key block
/// authentication code.
///
/// # Parameters
///
/// * `provider` - Cryptographic provider used for key derivation, AES-CMAC,
///   and AES-CBC decryption.
/// * `kbpk` - Provider-specific Key Block Protection Key.
/// * `kbpk_size` - AES size of the KBPK and derived keys.
/// * `key_block` - ASCII-encoded TR-31 key block.
///
/// # Returns
///
/// The parsed [`KeyBlockHeader`] and the unwrapped plaintext key material.
///
/// The key is returned as [`SecretKey`], which redacts its contents from
/// debug output and zeroizes its owned memory when dropped. Call
/// [`SecretKey::expose_secret`] when explicit access to the raw key bytes is
/// required.
///
/// # Errors
///
/// Returns [`Tr31CryptoError::Tr31`] if:
///
/// - the key block header cannot be parsed,
/// - the encoded key block length does not match the actual length,
/// - the key block is shorter than the required minimum,
/// - the key block version is unsupported,
/// - the encrypted payload or MAC is not valid hexadecimal,
/// - the decoded MAC does not have the required length,
/// - MAC verification fails,
/// - the decrypted payload is invalid.
///
/// Returns [`Tr31CryptoError::Crypto`] if the cryptographic provider reports
/// a key-derivation, AES-CBC decryption, or AES-CMAC calculation error.
pub fn tr31_unwrap<P, K: ?Sized>(
    provider: &P,
    kbpk: &K,
    kbpk_size: AesKeySize,
    key_block: &str,
) -> Result<(KeyBlockHeader, SecretKey), Tr31CryptoError<P::Error>>
where
    P: AesCmacKeyDerivation<K>
        + AesCbc<<P as AesCmacKeyDerivation<K>>::DerivedKey>
        + AesCmac<<P as AesCmacKeyDerivation<K>>::DerivedKey>,
{
    let header = KeyBlockHeader::new_from_str(key_block)?;

    let header_len = header.len();

    let key_block_len = key_block.len();

    let encoded_key_block_len = header.kb_length() as usize;

    if key_block_len != encoded_key_block_len {
        return Err(Tr31Error::KeyBlockLengthMismatch {
            expected: encoded_key_block_len,
            actual: key_block_len,
        }
        .into());
    }

    let min_key_block_len = 16 + (2 * TR31_D_BLOCK_LEN) + (2 * TR31_D_MAC_LEN);

    if key_block_len < min_key_block_len {
        return Err(Tr31Error::KeyBlockBelowMinimum {
            minimum: min_key_block_len,
            actual: key_block_len,
        }
        .into());
    }

    if header.version_id() != "D" {
        return Err(Tr31Error::UnsupportedVersion(header.version_id().to_string()).into());
    }

    let mac_hex_len = TR31_D_MAC_LEN * 2;

    let encrypted_payload_hex = &key_block[header_len..key_block_len - mac_hex_len];

    let mac_hex = &key_block[key_block_len - mac_hex_len..];

    // Derive KBEK and KBAK from the KBPK.
    let (kbek, kbak) =
        derive_keys_version_d(provider, kbpk, kbpk_size).map_err(Tr31CryptoError::Crypto)?;

    let encrypted_payload = hex::decode(encrypted_payload_hex)?;

    let mac = hex::decode(mac_hex)?;

    let iv: [u8; TR31_D_MAC_LEN] = mac.as_slice().try_into().map_err(|_| {
        Tr31CryptoError::Tr31(Tr31Error::InvalidMacLength {
            expected: TR31_D_MAC_LEN,
            actual: mac.len(),
        })
    })?;

    // Decrypt with KBEK.
    let decrypted_payload = Zeroizing::new(
        provider
            .decrypt_cbc(&kbek, &iv, &encrypted_payload)
            .map_err(Tr31CryptoError::Crypto)?,
    );

    // MAC input is the clear-text header followed by the plaintext payload.
    let mut mac_input = Zeroizing::new(key_block[..header_len].as_bytes().to_vec());

    mac_input.extend_from_slice(decrypted_payload.as_slice());

    // Authenticate with KBAK.
    let calculated_mac = provider
        .calculate_cmac(&kbak, mac_input.as_slice())
        .map_err(Tr31CryptoError::Crypto)?;

    if mac.as_slice() != calculated_mac.as_slice() {
        return Err(Tr31Error::MacVerificationFailed.into());
    }

    let key = extract_key_from_payload(decrypted_payload.as_slice())?;

    Ok((header, SecretKey::new(key)))
}
