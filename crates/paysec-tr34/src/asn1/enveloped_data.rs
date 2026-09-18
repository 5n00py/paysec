use cms::content_info::CmsVersion;
use cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfo, RecipientInfos};

use der::asn1::{Any, OctetString};

use spki::AlgorithmIdentifierOwned;

use zeroize::Zeroizing;

use crate::asn1::key_block::KeyBlock;
use crate::asn1::key_transport::build_key_transport_recipient_info;
use crate::oid::{ID_AES_128_CBC, ID_DATA};
use crate::{KdhCredential, KrdCredential, Tr34Error};

const AES_BLOCK_SIZE: usize = 16;

/// Encode the strict TR-34 KeyBlock and apply the CMS content-encryption
/// padding required before AES-CBC encryption.
///
/// The returned buffer contains the transported key in clear form and is
/// therefore zeroized on drop.
pub(crate) fn encode_padded_key_block(
    kdh_credential: &KdhCredential,
    clear_key: &[u8],
    key_block_header: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Tr34Error> {
    let encoded = KeyBlock::new(kdh_credential, clear_key, key_block_header).to_der()?;

    Ok(pad_cms_content(encoded))
}

/// Apply the CMS block-cipher padding defined by RFC 5652.
///
/// Padding is always added. If the input is already aligned to the AES
/// block size, a complete block containing `0x10` bytes is appended.
fn pad_cms_content(mut content: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let padding_len = AES_BLOCK_SIZE - (content.len() % AES_BLOCK_SIZE);

    content.extend(std::iter::repeat(padding_len as u8).take(padding_len));

    content
}

/// Construct the AES-128-CBC AlgorithmIdentifier used to encrypt the
/// TR-34 KeyBlock.
///
/// The algorithm parameters contain the 16-byte initialization vector as
/// an OCTET STRING.
pub(crate) fn aes_128_cbc_algorithm_identifier(
    iv: &[u8; AES_BLOCK_SIZE],
) -> Result<AlgorithmIdentifierOwned, Tr34Error> {
    let iv = OctetString::new(iv.as_slice())?;

    Ok(AlgorithmIdentifierOwned {
        oid: ID_AES_128_CBC,
        parameters: Some(Any::encode_from(&iv)?),
    })
}

/// Construct the CMS EncryptedContentInfo containing the encrypted
/// TR-34 KeyBlock.
pub(crate) fn build_encrypted_content_info(
    iv: &[u8; AES_BLOCK_SIZE],
    encrypted_key_block: &[u8],
) -> Result<EncryptedContentInfo, Tr34Error> {
    Ok(EncryptedContentInfo {
        content_type: ID_DATA,
        content_enc_alg: aes_128_cbc_algorithm_identifier(iv)?,
        encrypted_content: Some(OctetString::new(encrypted_key_block.to_vec())?),
    })
}

/// Construct the inner CMS EnvelopedData used by TR-34.
///
/// `encrypted_ephemeral_key` is KE encrypted for the KRD using
/// RSAES-OAEP-SHA256.
///
/// `encrypted_key_block` is the padded KeyBlock encrypted under KE using
/// AES-128-CBC with `iv`.
pub(crate) fn build_enveloped_data(
    krd_credential: &KrdCredential,
    encrypted_ephemeral_key: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
    encrypted_key_block: &[u8],
) -> Result<EnvelopedData, Tr34Error> {
    let recipient_info =
        build_key_transport_recipient_info(krd_credential, encrypted_ephemeral_key)?;

    let recip_infos = RecipientInfos::try_from(vec![RecipientInfo::Ktri(recipient_info)])?;

    Ok(EnvelopedData {
        version: CmsVersion::V0,
        originator_info: None,
        recip_infos,
        encrypted_content: build_encrypted_content_info(iv, encrypted_key_block)?,
        unprotected_attrs: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use der::{Decode, Encode};

    use paysec_crypto::AesCbc;

    use paysec_crypto_rustcrypto::RustCryptoProvider;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../../tests/fixtures/kdh-certificate.der");

    const KRD_CERTIFICATE_DER: &[u8] = include_bytes!("../../tests/fixtures/krd-certificate.der");

    #[test]
    fn cms_padding_pads_key_block_to_aes_boundary() {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let padded = encode_padded_key_block(&credential, &clear_key, b"A0256K0TB00E0000").unwrap();

        // Strict KeyBlock DER is 117 bytes.
        // CMS therefore adds eleven 0x0B bytes.
        assert_eq!(padded.len(), 128);

        assert_eq!(&padded[117..], &[0x0B; 11],);
    }

    #[test]
    fn cms_padding_adds_complete_block_when_aligned() {
        let content = Zeroizing::new(vec![0xAA; 16]);

        let padded = pad_cms_content(content);

        assert_eq!(padded.len(), 32);

        assert_eq!(&padded[16..], &[0x10; 16],);
    }

    #[test]
    fn aes_128_cbc_algorithm_identifier_contains_iv() {
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let algorithm = aes_128_cbc_algorithm_identifier(&iv).unwrap();

        let encoded = algorithm.to_der().unwrap();

        let expected = hex::decode(
            "301D\
             0609608648016503040102\
             0410\
             000102030405060708090A0B0C0D0E0F",
        )
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn encrypts_strict_key_block_with_aes_128_cbc() {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let padded = encode_padded_key_block(&credential, &clear_key, b"A0256K0TB00E0000").unwrap();

        let ephemeral_key = hex::decode("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0").unwrap();

        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let provider = RustCryptoProvider::new();

        let encrypted = provider
            .encrypt_cbc(ephemeral_key.as_slice(), &iv, padded.as_slice())
            .unwrap();

        let expected = hex::decode(
            "7E817CE6F591CDAD7D50079032F8D824\
             8287A599C699B2DDA97550DB9B7C7DB4\
             5EADCF2C2FE88134B38618985E19DAC0\
             50D7915D95053B360A7D17F54C3A481A\
             081DDD821ADB1C88F859DC2FC8DFF432\
             DBC706473758E227DA117781F59AD616\
             78F0A750D0EC2DA877F8800985B1DCC\
             907C252FE0BFE162FD227D11F635A4547",
        )
        .unwrap();

        assert_eq!(encrypted, expected);
    }

    #[test]
    fn builds_enveloped_data_for_encrypted_key_block() {
        let kdh_credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let krd_credential = KrdCredential::from_der(KRD_CERTIFICATE_DER).unwrap();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let padded =
            encode_padded_key_block(&kdh_credential, &clear_key, b"A0256K0TB00E0000").unwrap();

        let ephemeral_key = hex::decode("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0").unwrap();

        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let provider = RustCryptoProvider::new();

        let encrypted_key_block = provider
            .encrypt_cbc(ephemeral_key.as_slice(), &iv, padded.as_slice())
            .unwrap();

        // RSA-OAEP itself is already covered by key_transport tests.
        // Here we keep this test focused on EnvelopedData assembly.
        let encrypted_ephemeral_key = vec![0xAA; 256];

        let enveloped_data = build_enveloped_data(
            &krd_credential,
            &encrypted_ephemeral_key,
            &iv,
            &encrypted_key_block,
        )
        .unwrap();

        assert_eq!(enveloped_data.version, CmsVersion::V0);

        assert!(enveloped_data.originator_info.is_none());

        assert!(enveloped_data.unprotected_attrs.is_none());

        assert_eq!(enveloped_data.encrypted_content.content_type, ID_DATA);

        assert_eq!(
            enveloped_data.encrypted_content.content_enc_alg,
            aes_128_cbc_algorithm_identifier(&iv,).unwrap()
        );

        assert_eq!(
            enveloped_data
                .encrypted_content
                .encrypted_content
                .as_ref()
                .unwrap()
                .as_bytes(),
            encrypted_key_block.as_slice()
        );

        let encoded = enveloped_data.to_der().unwrap();

        let decoded = EnvelopedData::from_der(&encoded).unwrap();

        assert_eq!(decoded, enveloped_data);
    }
}
