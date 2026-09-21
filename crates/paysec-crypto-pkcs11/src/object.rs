use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use crate::key::KeySelector;
use crate::{Pkcs11Error, Pkcs11Key};

pub(crate) fn resolve_key(
    session: &Session,
    key: &Pkcs11Key,
    class: ObjectClass,
    key_type: KeyType,
) -> Result<ObjectHandle, Pkcs11Error> {
    let template = key_search_template(key, class, key_type);

    let mut objects = session
        .find_objects(&template)
        .map_err(|error| Pkcs11Error::cryptoki("failed to search for PKCS #11 key", error))?;

    match objects.len() {
        0 => Err(Pkcs11Error::new("no matching PKCS #11 key found")),

        1 => Ok(objects.remove(0)),

        _ => Err(Pkcs11Error::new(
            "multiple PKCS #11 keys matched the selector",
        )),
    }
}

fn key_search_template(key: &Pkcs11Key, class: ObjectClass, key_type: KeyType) -> Vec<Attribute> {
    let mut template = vec![Attribute::Class(class), Attribute::KeyType(key_type)];

    match key.selector() {
        KeySelector::Id(id) => {
            template.push(Attribute::Id(id.clone()));
        }

        KeySelector::Label(label) => {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
        }
    }

    template
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_key_search_template_for_id() {
        let key = Pkcs11Key::by_id([0x01, 0x02]);

        let template = key_search_template(&key, ObjectClass::SECRET_KEY, KeyType::AES);

        assert_eq!(
            template,
            vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Id(vec![0x01, 0x02]),
            ]
        );
    }

    #[test]
    fn builds_key_search_template_for_label() {
        let key = Pkcs11Key::by_label("aes-key");

        let template = key_search_template(&key, ObjectClass::SECRET_KEY, KeyType::AES);

        assert_eq!(
            template,
            vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Label(b"aes-key".to_vec()),
            ]
        );
    }
}
