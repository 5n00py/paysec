use spki::ObjectIdentifier;

pub(crate) const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

pub(crate) const RSAES_OAEP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");

pub(crate) const ID_AES_128_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
