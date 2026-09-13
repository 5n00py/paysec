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
/// # Defined Key Usage Values (TR-31: 2018, p. 20-21)
///
/// - `B0`: BDK Base Derivation Key - Used to derive the Initial DUKPT Key in DUKPT process.
/// - `B1`: Initial DUKPT Key - Sent to a PIN Entry Device as the initial key in a DUKPT key management scheme.
/// - `B2`: Base Key Variant Key - Used to create key variants from the Base Key Variant.
/// - `C0`: CVK Card Verification Key - Used to compute or verify card verification codes (e.g., CVV, CVC).
/// - `D0`: Symmetric Key for Data Encryption - Used for encrypting data.
/// - `D1`: Asymmetric Key for Data Encryption - Used for encrypting data with asymmetric algorithms.
/// - `D2`: Data Encryption Key for Decimalization Table - Used in specific data encryption scenarios.
/// - `E0`: EMV/chip Issuer Master Keys - Application cryptograms.
/// - `E1`: EMV/chip Issuer Master Keys - Secure Messaging for Confidentiality.
/// - `E2`: EMV/chip Issuer Master Keys - Secure Messaging for Integrity.
/// - `E3`: EMV/chip Issuer Master Keys - Data Authentication Code.
/// - `E4`: EMV/chip Issuer Master Keys - Dynamic Numbers.
/// - `E5`: EMV/chip Issuer Master Keys - Card Personalization.
/// - `E6`: EMV/chip Issuer Master Keys - Other.
/// - `I0`: Initialization Vector.
/// - `K0`: Key Encryption or Wrapping - Used for key encryption or wrapping operations.
/// - `K1`: TR-31 Key Block Protection Key - Used specifically in TR-31 key block protection.
/// - `K2`: TR-34 Asymmetric key - Used for TR-34 related asymmetric cryptographic operations.
/// - `K3`: Asymmetric Key for Key Agreement/Key Wrapping - Used in key agreement or wrapping using asymmetric cryptography
/// - `M0`: ISO 16609 MAC algorithm 1 (using TDEA).
/// - `M1`: ISO 9797-1 MAC Algorithm 1
/// - `M2`: ISO 9797-1 MAC Algorithm 2
/// - `M3`: ISO 9797-1 MAC Algorithm 3
/// - `M4`: ISO 9797-1 MAC Algorithm 4
/// - `M5`: ISO 9797-1:1999 MAC Algorithm 5
/// - `M6`: ISO 9797-1:2011 MAC Algorithm 5/CMAC
/// - `M7`: HMAC
/// - `M8`: ISO 9797-1:2011 MAC Algorithm 6
/// - `P0`: PIN Encryption - Used for encrypting PIN data.
/// - `S0`: Asymmetric Key Pair for Digital Signature - Used for digital signing operations.
/// - `S1`: Asymmetric Key Pair, CA key
/// - `S2`: Asymmetric Key Pair, nonX9.24 key
/// - `V0`: PIN verification, KPV, other algorithm
/// - `V1`: PIN verification, IBM 3624
/// - `V2`: PIN verification, VISA PVV
/// - `V3`: PIN Verification, X9.132 algorithm 1
/// - `V4`: PIN Verification, X9.132 algorithm 2
///
/// Note: Nomeric values are reserved for proprietary use and not implemented. Some usages are
/// appropriate for both symmetric and asymmetric keys (e.g., `K0` for TDEA KEK and RSA key
/// exchange key).
pub const ALLOWED_KEY_USAGES: [&'static str; 29] = [
    "B0", "B1", "B2", "C0", "D0", "D1", "D2", "E0", "E1", "E2", "E3", "E4", "E5", "E6", "K0", "K1",
    "K2", "K3", "M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "P0", "S0",
];

/// Predefined allowed algorithms for the key block.
///
/// The algorithm byte in the key block header defines the cryptographic algorithm that can be used with the key.
/// The algorithm is identified by byte 7 in the key block header.
///
/// # Defined Algorithm Values (TR-31: 2018, p. 24)
///
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
/// # Defined Mode of Use Values (TR-31: 2018, p. 24)
///
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
/// # Defined Exportability Values (TR-31: 2018, p. 26)
///
/// - `E`: Exportable under a Key Encryption Key (KEK) in a form meeting the requirements of X9.24 Parts 1 or 2.
/// - `N`: Non-exportable by the receiver of the key block or from storage. This does not preclude exporting keys
///         derived from a non-exportable key.
/// - `S`: Sensitive. Exportable under a KEK in a form not necessarily meeting the requirements of X9.24 Parts 1 or 2.
///
/// Note: Numeric values are reserved for proprietary use.
pub const ALLOWED_EXPORTABILITIES: [&'static str; 3] = ["E", "N", "S"];

/// Predefined allowed optional block IDs for the key block.
///
/// The Optional Block IDs in the key block header provide a mechanism for including additional,
/// non-standard data within a TR-31 key block. Each optional block is identified by a unique two-character
/// ASCII string.
///
/// # Defined Optional Block ID Values (TR-31: 2018, p. 28-29)
///
/// - `CT`: Asymmetric public key certificate. Format details are defined in the TR-31 specification.
/// - `HM`: Hash algorithm for HMAC.
/// - `IK`: Initial Key Identifier for the Initial DUKPT Key. The Initial Key ID is the concatenation
///         of the BDK ID and the Derivation ID encoded in hex-ASCII. For AES DUKPT, it is 16 hex-ASCII
///         characters in length. This value is used to instantiate the use of the Initial DUKPT key on the
///         receiving device and it identifies the Initial Key derived from a BDK.
/// - `KC`: Key Check Value of wrapped key; computed according to X9.24-1-2017 Annex A. Not used as an
///         integrity mechanism.
/// - `KP`: Key Check Value of KBPK; computed according to X9.24-1-2017 Annex A. Not used as an
///         integrity mechanism.
/// - `KS`: Key Set Identifier, encoded in hex-ASCII; optionally used to identify the key within a system.
/// - `KV`: Key Block Values: Informational field indicating the version of the key block field values.
/// - `PB`: Padding field used as the last Optional Block. The padding block is used to bring the total length
///         of all Optional Blocks in the key block to a multiple of the encryption block length. The data
///         bytes in this block are filled with readable ASCII characters.
/// - `TS`: Time Stamp; the time and date (in UTC Time format) that indicates when the key block was formed.
///
/// Note: Numeric values are reserved for proprietary use.$
pub const ALLOWED_OPT_BLOCK_IDS: [&'static str; 9] =
    ["CT", "HM", "IK", "KC", "KP", "KS", "KV", "PB", "TS"];
