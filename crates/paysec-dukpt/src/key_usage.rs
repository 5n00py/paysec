/// Purpose of an ANSI X9.24-3 AES DUKPT working key.
///
/// The selected usage is encoded into the derivation data so that working
/// keys derived for different purposes are cryptographically separated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkingKeyUsage {
    /// Key encryption key.
    KeyEncryption,

    /// PIN encryption key.
    PinEncryption,

    /// Message-authentication key for MAC generation.
    MessageAuthenticationGeneration,

    /// Message-authentication key for MAC verification.
    MessageAuthenticationVerification,

    /// Message-authentication key usable in both directions.
    MessageAuthenticationBothWays,

    /// Data-encryption key for encryption.
    DataEncryptionEncrypt,

    /// Data-encryption key for decryption.
    DataEncryptionDecrypt,

    /// Data-encryption key usable in both directions.
    DataEncryptionBothWays,

    /// Key used for further key derivation.
    KeyDerivation,
}

impl WorkingKeyUsage {
    pub(crate) const fn indicator(self) -> u16 {
        match self {
            Self::KeyEncryption => 0x0002,
            Self::PinEncryption => 0x1000,

            Self::MessageAuthenticationGeneration => 0x2000,
            Self::MessageAuthenticationVerification => 0x2001,
            Self::MessageAuthenticationBothWays => 0x2002,

            Self::DataEncryptionEncrypt => 0x3000,
            Self::DataEncryptionDecrypt => 0x3001,
            Self::DataEncryptionBothWays => 0x3002,

            Self::KeyDerivation => 0x8000,
        }
    }
}
