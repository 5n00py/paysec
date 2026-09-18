use cms::cert::IssuerAndSerialNumber;
use cms::signed_data::SignerIdentifier;

use der::asn1::OctetStringRef;
use der::{Encode, Sequence};

use zeroize::Zeroizing;

use crate::Error;

const KEY_BLOCK_VERSION_V1: u8 = 0;

/// Logical TR-34 key block.
///
/// The logical representation is deliberately separated from its ASN.1
/// representation so alternative interoperability encodings can be added
/// without changing the protocol model.
pub(crate) struct KeyBlock<'a> {
    id_kdh: &'a IssuerAndSerialNumber,
    clear_key: &'a [u8],
    key_block_header: &'a [u8],
}

impl<'a> KeyBlock<'a> {
    pub(crate) const fn new(
        id_kdh: &'a IssuerAndSerialNumber,
        clear_key: &'a [u8],
        key_block_header: &'a [u8],
    ) -> Self {
        Self {
            id_kdh,
            clear_key,
            key_block_header,
        }
    }

    pub(crate) fn to_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let clear_key = OctetStringRef::new(self.clear_key)?;
        let key_block_header = OctetStringRef::new(self.key_block_header)?;

        let key_block = KeyBlockAsn1 {
            version: KEY_BLOCK_VERSION_V1,
            id_kdh: SignerIdentifier::IssuerAndSerialNumber(self.id_kdh.clone()),
            clear_key,
            key_block_header,
        };

        Ok(Zeroizing::new(key_block.to_der()?))
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
struct KeyBlockAsn1<'a> {
    version: u8,
    id_kdh: SignerIdentifier,
    clear_key: OctetStringRef<'a>,
    key_block_header: OctetStringRef<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use der::Decode;

    #[test]
    fn encodes_normative_key_block() {
        let id_kdh_der = hex::decode(
            "304A\
             3041\
             310B3009060355040613025553\
             31153013060355040A130C545233342053616D706C6573\
             311B301906035504031312545233342053616D706C65204341204B4448\
             02053400000006",
        )
        .unwrap();

        let id_kdh = IssuerAndSerialNumber::from_der(&id_kdh_der).unwrap();

        let clear_key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();

        let key_block_header = b"A0256K0TB00E0000";

        let key_block = KeyBlock::new(&id_kdh, &clear_key, key_block_header);

        let encoded = key_block.to_der().unwrap();

        let expected = hex::decode(
            "3073\
             020100\
             304A\
             3041\
             310B3009060355040613025553\
             31153013060355040A130C545233342053616D706C6573\
             311B301906035504031312545233342053616D706C65204341204B4448\
             02053400000006\
             04100123456789ABCDEFFEDCBA9876543210\
             041041303235364B30544230304530303030",
        )
        .unwrap();

        assert_eq!(encoded.as_slice(), expected);
    }
}
