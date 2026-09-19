use cms::signed_data::SignerIdentifier;

use der::asn1::{Any, ObjectIdentifier, OctetStringRef, SetOfVec};
use der::{Encode, Sequence};

use zeroize::Zeroizing;

use crate::oid::ID_DATA;
use crate::profile::{KeyBlockHeaderEncoding, KeyBlockVersionEncoding};
use crate::{KdhCredential, Tr34Error};

const KEY_BLOCK_VERSION_ANNEX_D: u8 = 0;
const KEY_BLOCK_VERSION_ANNEX_B: u8 = 1;

/// Logical TR-34 key block.
///
/// The logical representation is deliberately separated from its ASN.1
/// representation so alternative interoperability encodings can be selected
/// without changing the protocol model.
pub(crate) struct KeyBlock<'a> {
    kdh_credential: &'a KdhCredential,
    clear_key: &'a [u8],
    key_block_header: &'a [u8],
}

impl<'a> KeyBlock<'a> {
    pub(crate) const fn new(
        kdh_credential: &'a KdhCredential,
        clear_key: &'a [u8],
        key_block_header: &'a [u8],
    ) -> Self {
        Self {
            kdh_credential,
            clear_key,
            key_block_header,
        }
    }

    pub(crate) fn to_der(
        &self,
        version_encoding: KeyBlockVersionEncoding,
        header_encoding: KeyBlockHeaderEncoding,
    ) -> Result<Zeroizing<Vec<u8>>, Tr34Error> {
        let clear_key = OctetStringRef::new(self.clear_key)?;

        match (version_encoding, header_encoding) {
            (KeyBlockVersionEncoding::AnnexD, KeyBlockHeaderEncoding::BareOctetString) => {
                let key_block_header = OctetStringRef::new(self.key_block_header)?;

                let key_block = StrictKeyBlockAsn1 {
                    version: KEY_BLOCK_VERSION_ANNEX_D,

                    id_kdh: SignerIdentifier::IssuerAndSerialNumber(
                        self.kdh_credential.issuer_and_serial_number(),
                    ),

                    clear_key,

                    key_block_header,
                };

                Ok(Zeroizing::new(key_block.to_der()?))
            }

            (KeyBlockVersionEncoding::AnnexBSample, KeyBlockHeaderEncoding::DataAttribute) => {
                let key_block_header = OctetStringRef::new(self.key_block_header)?;

                let key_block_header_value = Any::encode_from(&key_block_header)?;

                let key_block_header = AnnexBKeyBlockHeaderAttribute {
                    oid: ID_DATA,

                    values: SetOfVec::try_from(vec![key_block_header_value])?,
                };

                let key_block = AnnexBKeyBlockAsn1 {
                    version: KEY_BLOCK_VERSION_ANNEX_B,

                    id_kdh: SignerIdentifier::IssuerAndSerialNumber(
                        self.kdh_credential.issuer_and_serial_number(),
                    ),

                    clear_key,

                    key_block_header,
                };

                Ok(Zeroizing::new(key_block.to_der()?))
            }

            _ => unreachable!("unsupported internal KeyBlock encoding combination"),
        }
    }
}

/// Normative TR-34 Annex D encoding.
///
/// KeyBlock ::= SEQUENCE {
///     version        INTEGER { v1(0) } (v1,...),
///     idKDH          SignerIdentifier,
///     clearKey       OCTET STRING,
///     keyBlockHeader OCTET STRING
/// }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct StrictKeyBlockAsn1<'a> {
    version: u8,
    id_kdh: SignerIdentifier,
    clear_key: OctetStringRef<'a>,
    key_block_header: OctetStringRef<'a>,
}

/// KeyBlock representation used by the Annex B examples.
///
/// The sample uses version INTEGER 1 and represents the KBH as an
/// `id-data` Attribute rather than the bare OCTET STRING specified by
/// Annex D.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AnnexBKeyBlockAsn1<'a> {
    version: u8,
    id_kdh: SignerIdentifier,
    clear_key: OctetStringRef<'a>,
    key_block_header: AnnexBKeyBlockHeaderAttribute,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AnnexBKeyBlockHeaderAttribute {
    oid: ObjectIdentifier,
    values: SetOfVec<Any>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDH_CERTIFICATE_DER: &[u8] = include_bytes!("../../tests/fixtures/kdh-certificate.der");

    const ANNEX_B_KDH_CERTIFICATE_DER: &[u8] =
        include_bytes!("../../tests/fixtures/tr34-2019/kdh-1-certificate.der");

    const ANNEX_B_AES_KEY_BLOCK_DER: &[u8] =
        include_bytes!("../../tests/fixtures/tr34-2019/aes-key-block.der");

    #[test]
    fn encodes_normative_key_block() {
        let credential = KdhCredential::from_der(KDH_CERTIFICATE_DER).unwrap();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let key_block_header = b"A0256K0TB00E0000";

        let key_block = KeyBlock::new(&credential, &clear_key, key_block_header);

        let encoded = key_block
            .to_der(
                KeyBlockVersionEncoding::AnnexD,
                KeyBlockHeaderEncoding::BareOctetString,
            )
            .unwrap();

        let expected = hex::decode(concat!(
            "3073",
            "020100",
            "304A",
            "3041",
            "310B3009060355040613025553",
            "31153013060355040A130C545233342053616D706C6573",
            "311B301906035504031312545233342053616D706C65204341204B4448",
            "02053400000006",
            "04100123456789ABCDEFFEDCBA9876543210",
            "041041303235364B30544230304530303030",
        ))
        .unwrap();

        assert_eq!(encoded.as_slice(), expected,);
    }

    #[test]
    fn encodes_annex_b_aes_key_block_fixture() {
        let credential = KdhCredential::from_der(ANNEX_B_KDH_CERTIFICATE_DER).unwrap();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let key_block = KeyBlock::new(&credential, &clear_key, b"D0256K0AB00E0000");

        let encoded = key_block
            .to_der(
                KeyBlockVersionEncoding::AnnexBSample,
                KeyBlockHeaderEncoding::DataAttribute,
            )
            .unwrap();

        assert_eq!(encoded.as_slice(), ANNEX_B_AES_KEY_BLOCK_DER,);
    }
}
