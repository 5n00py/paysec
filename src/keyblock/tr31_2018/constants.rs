/// Predefined allowed version IDs for the key block.
///
/// Each version ID corresponds to a different method of cryptographic protection and layout of the key block:
/// - `A` (0x41): Key block protected using the Key Variant Binding Method.
///   This version is deprecated and should not be used in new applications.
/// - `B` (0x42): Key block protected using the TDEA Key Derivation Binding Method.
///   Version B is preferred for new TDEA implementations.
/// - `C` (0x43): Key block protected using the TDEA Key Variant Binding Method.
/// - `D` (0x44): Key block protected using the AES Key Derivation Binding Method.
///
/// Note: Numeric key block Version IDs are reserved for proprietary key block definitions.
///       Multiple key block versions may be in use at any time.
///       It is not recommended that Version ‘B’ or ‘C’ blocks be converted to version ‘A’ blocks.
///       Currently only version `D` is implemented in the wrapping mechanisms.
pub const ALLOWED_VERSION_IDS: [&'static str; 4] = ["A", "B", "C", "D"];

/// Predefined allowed key usages for the key block.
///
/// Key usage defines the type of the key and its intended function, whether it's used for encrypting data,
/// calculating a MAC, etc. The key usage is identified by bytes 5 and 6 in the key block header.
///
/// # Defined Key Usage Values
/// - `B0`: BDK Base Derivation Key - Used to derive the Initial DUKPT Key in DUKPT process.
/// - `B1`: Initial DUKPT Key - Sent to a PIN Entry Device as the initial key in a DUKPT key management scheme.
/// - `B2`: Base Key Variant Key - Used to create key variants from the Base Key Variant.
/// - `C0`: CVK Card Verification Key - Used to compute or verify card verification codes (e.g., CVV, CVC).
/// - `D0`: Symmetric Key for Data Encryption - Used for encrypting data.
/// - `D1`: Asymmetric Key for Data Encryption - Used for encrypting data with asymmetric algorithms.
/// - `D2`: Data Encryption Key for Decimalization Table - Used in specific data encryption scenarios.
/// - `E0` to `E6`: EMV/chip Issuer Master Keys - Used for various purposes in EMV/chip transactions.
/// - `K0`: Key Encryption or Wrapping - Used for key encryption or wrapping operations.
/// - `K1`: TR-31 Key Block Protection Key - Used specifically in TR-31 key block protection.
/// - `K2`: TR-34 Asymmetric key - Used for TR-34 related asymmetric cryptographic operations.
/// - `K3`: Asymmetric Key for Key Agreement/Key Wrapping - Used in key agreement or wrapping using asymmetric cryptography.
/// - `M0` to `M8`: MAC Algorithms - Used for various Message Authentication Code (MAC) generation algorithms.
/// - `P0`: PIN Encryption - Used for encrypting PIN data.
/// - `S0`: Asymmetric Key Pair for Digital Signature - Used for digital signing operations.
///
/// Note: This list of usages is not exhaustive and may include other key usage types in future versions.
/// Some usages are appropriate for both symmetric and asymmetric keys (e.g., `K0` for TDEA KEK and RSA key exchange key).
pub const ALLOWED_KEY_USAGES: [&'static str; 29] = [
    "B0", "B1", "B2", "C0", "D0", "D1", "D2", "E0", "E1", "E2", "E3", "E4", "E5", "E6", "K0", "K1",
    "K2", "K3", "M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "P0", "S0",
];

/// Predefined allowed algorithms for the key block.
///
/// The algorithm byte in the key block header defines the cryptographic algorithm that can be used with the key.
/// The algorithm is identified by byte 7 in the key block header.
///
/// # Defined Algorithm Values
/// - `A`: AES - Advanced Encryption Standard.
/// - `D`: DEA - Data Encryption Algorithm. Included for backward compatibility.
/// - `E`: Elliptic Curve - Used in elliptic curve cryptography.
/// - `H`: HMAC - Keyed-Hash Message Authentication Code. The underlying hash algorithm should be specified in an optional field.
/// - `R`: RSA - Rivest-Shamir-Adleman. A widely used asymmetric encryption algorithm.
/// - `S`: DSA - Digital Signature Algorithm. Included for future reference.
/// - `T`: TDEA - Triple Data Encryption Algorithm. Also known as Triple DES.
///
/// Note: Numeric values are reserved for proprietary use.
pub const ALLOWED_ALGORITHMS: [&'static str; 7] = ["A", "D", "E", "H", "R", "S", "T"];

/// Predefined allowed modes of use for the key block.
///
/// The Mode of Use byte in the key block header defines the operation that the key can perform.
/// It is identified by byte 8 in the key block header.
///
/// # Defined Mode of Use Values
/// - `B`: Both Encrypt & Decrypt / Wrap & Unwrap.
/// - `C`: Both Generate & Verify.
/// - `D`: Decrypt / Unwrap Only.
/// - `E`: Encrypt / Wrap Only.
/// - `G`: Generate Only.
/// - `N`: No special restrictions (other than restrictions implied by the Key Usage).
/// - `S`: Signature Only.
/// - `T`: Both Sign & Decrypt.
/// - `V`: Verify Only.
/// - `X`: Key used to derive other key(s).
/// - `Y`: Key used to create key variants.
///
/// Note: Numeric values are reserved for proprietary use.
pub const ALLOWED_MODES_OF_USE: [&'static str; 11] =
    ["B", "C", "D", "E", "G", "N", "S", "T", "V", "X", "Y"];

/// Predefined allowed exportabilities for the key block.
///
/// The Exportability byte in the key block header (byte 11) indicates the conditions under which
/// the protected key may be transferred outside its cryptographic domain. This includes secure backup
/// provisions and special handling requirements for keys with unique security assumptions.
///
/// # Defined Exportability Values
/// - `E`: Exportable under a Key Encryption Key (KEK) in a form meeting the requirements of X9.24 Parts 1 or 2.
/// - `N`: Non-exportable by the receiver of the key block or from storage. This does not preclude exporting keys
///         derived from a non-exportable key.
/// - `S`: Sensitive. Exportable under a KEK in a form not necessarily meeting the requirements of X9.24 Parts 1 or 2.
///
/// Note: Numeric values are reserved for proprietary use.
pub const ALLOWED_EXPORTABILITIES: [&'static str; 3] = ["E", "N", "S"];
