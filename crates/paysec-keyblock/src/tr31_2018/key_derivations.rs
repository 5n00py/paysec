use paysec_crypto::{AesCmacKeyDerivation, AesKeySize};

use std::error::Error;

// Input Data for Key Derivation Binding Method - AES

// AES-128
const AES_128_KDI_KBEK: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80];

const AES_128_KDI_KBAK: [u8; 8] = [0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x80];

// AES-192
const AES_192_KDI_KBEK_1: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0];

const AES_192_KDI_KBEK_2: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0];

const AES_192_KDI_KBAK_1: [u8; 8] = [0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0];

const AES_192_KDI_KBAK_2: [u8; 8] = [0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0];

// AES-256
const AES_256_KDI_KBEK_1: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00];

const AES_256_KDI_KBEK_2: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00];

const AES_256_KDI_KBAK_1: [u8; 8] = [0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00];

const AES_256_KDI_KBAK_2: [u8; 8] = [0x02, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00];

/// Derive the Key Block Encryption Key (KBEK) and Key Block Authentication
/// Key (KBAK) for a TR-31 version D key block.
///
/// TR-31 version D uses the AES Key Derivation Binding Method. The KBPK is
/// used with AES-CMAC and the appropriate derivation input data to produce
/// KBEK and KBAK.
///
/// Cryptographic key derivation is delegated to the supplied provider. The
/// resulting key representation is therefore provider-specific. A software
/// provider may return raw key bytes, while an HSM-backed provider may return
/// opaque key handles.
///
/// # Parameters
///
/// * `provider` - Cryptographic provider used to perform AES-CMAC key
///   derivation.
/// * `kbpk` - Provider-specific Key Block Protection Key.
/// * `key_size` - AES key size of the KBPK and derived KBEK/KBAK.
///
/// # Returns
///
/// A tuple containing:
///
/// 1. the derived KBEK,
/// 2. the derived KBAK.
///
/// Both values use the provider's [`AesCmacKeyDerivation::DerivedKey`] type.
///
/// # Errors
///
/// Returns an error if the cryptographic provider cannot perform the requested
/// key derivation.
pub fn derive_keys_version_d<P, K: ?Sized>(
    provider: &P,
    kbpk: &K,
    key_size: AesKeySize,
) -> Result<(P::DerivedKey, P::DerivedKey), Box<dyn Error>>
where
    P: AesCmacKeyDerivation<K>,
{
    match key_size {
        AesKeySize::Bits128 => {
            let kbek = provider.derive_key_cmac(kbpk, &[&AES_128_KDI_KBEK], 16)?;

            let kbak = provider.derive_key_cmac(kbpk, &[&AES_128_KDI_KBAK], 16)?;

            Ok((kbek, kbak))
        }

        AesKeySize::Bits192 => {
            let kbek =
                provider.derive_key_cmac(kbpk, &[&AES_192_KDI_KBEK_1, &AES_192_KDI_KBEK_2], 24)?;

            let kbak =
                provider.derive_key_cmac(kbpk, &[&AES_192_KDI_KBAK_1, &AES_192_KDI_KBAK_2], 24)?;

            Ok((kbek, kbak))
        }

        AesKeySize::Bits256 => {
            let kbek =
                provider.derive_key_cmac(kbpk, &[&AES_256_KDI_KBEK_1, &AES_256_KDI_KBEK_2], 32)?;

            let kbak =
                provider.derive_key_cmac(kbpk, &[&AES_256_KDI_KBAK_1, &AES_256_KDI_KBAK_2], 32)?;

            Ok((kbek, kbak))
        }
    }
}
