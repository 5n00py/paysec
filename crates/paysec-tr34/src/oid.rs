use spki::ObjectIdentifier;

pub(crate) const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

pub(crate) const ID_ENVELOPED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

pub(crate) const ID_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

pub(crate) const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

pub(crate) const ID_RANDOM_NONCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.25.3");

pub(crate) const RSAES_OAEP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");

pub(crate) const ID_AES_128_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
