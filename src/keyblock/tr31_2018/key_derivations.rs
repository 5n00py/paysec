use soft_aes::aes::aes_cmac;
use std::error::Error;

// Input Data for Key Derivation Binding Method - AES

// AES 128 bit
const AES_128_KDI_KBEK: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80];
const AES_128_KDI_KBAK: [u8; 8] = [0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x80];

// AES 192 bit
const AES_192_KDI_KBEK_1: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0];
const AES_192_KDI_KBEK_2: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0];
const AES_192_KDI_KBAK_1: [u8; 8] = [0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0];
const AES_192_KDI_KBAK_2: [u8; 8] = [0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0];

// AES 256 bit
const AES_256_KDI_KBEK_1: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00];
const AES_256_KDI_KBEK_2: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00];
const AES_256_KDI_KBAK_1: [u8; 8] = [0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00];
const AES_256_KDI_KBAK_2: [u8; 8] = [0x02, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00];

/// Derive the Key Block Encryption Key (KBEK) and the Key Block Authentication Key (KBAK)
/// for TR-31 Key Block Version ID 'D' using AES-CMAC.
///
/// This function uses the AES Key Derivation Binding Method to derive KBEK and KBAK from
/// the Key Block Protection Key (KBPK). The length of the derived keys (KBEK and KBAK) is
/// equal to the length of the KBPK.
///
/// # Arguments
///
/// * `kbpk` - The Key Block Protection Key (KBPK) as a byte slice.
///
/// # Returns
///
/// This function returns a `Result` containing a tuple of two `Vec<u8>` elements:
/// - The first element is the derived Key Block Encryption Key (KBEK).
/// - The second element is the derived Key Block Authentication Key (KBAK).
/// If an error occurs, such as an invalid KBPK length or an issue during the AES-CMAC
/// calculation, the function returns a `Box<dyn Error>`.
///
/// # Errors
///
/// This function returns an error if the KBPK length is not one of the expected sizes
/// (16, 24, or 32 bytes) or if there is an issue during the AES-CMAC calculation.
pub fn derive_keys_version_d(kbpk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    match kbpk.len() {
        16 => {
            // Derive AES-128 Encryption and Authentication Key
            let kbek = aes_cmac(&AES_128_KDI_KBEK, kbpk)?.to_vec();
            let kbak = aes_cmac(&AES_128_KDI_KBAK, kbpk)?.to_vec();
            Ok((kbek, kbak))
        }
        24 => {
            // Derive AES-192 Encryption and Authentication Key
            let mut kbek = aes_cmac(&AES_192_KDI_KBEK_1, kbpk)?.to_vec();
            kbek.extend_from_slice(&aes_cmac(&AES_192_KDI_KBEK_2, kbpk)?.to_vec());
            kbek.truncate(24); // Truncate to 24 bytes for AES-192

            let mut kbak = aes_cmac(&AES_192_KDI_KBAK_1, kbpk)?.to_vec();
            kbak.extend_from_slice(&aes_cmac(&AES_192_KDI_KBAK_2, kbpk)?.to_vec());
            kbak.truncate(24); // Truncate to 24 bytes for AES-192

            Ok((kbek, kbak))
        }
        32 => {
            // Derive AES-256 Encryption and Authentication Key
            let mut kbek = aes_cmac(&AES_256_KDI_KBEK_1, kbpk)?.to_vec();
            kbek.extend_from_slice(&aes_cmac(&AES_256_KDI_KBEK_2, kbpk)?.to_vec());
            let mut kbak = aes_cmac(&AES_256_KDI_KBAK_1, kbpk)?.to_vec();
            kbak.extend_from_slice(&aes_cmac(&AES_256_KDI_KBAK_2, kbpk)?.to_vec());
            Ok((kbek, kbak))
        }
        _ => Err("ERROR TR-31: Invalid KBPK length".into()),
    }
}
