#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeySelector {
    Id(Vec<u8>),
    Label(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11Key {
    selector: KeySelector,
}

impl Pkcs11Key {
    pub fn by_id(id: impl Into<Vec<u8>>) -> Self {
        Self {
            selector: KeySelector::Id(id.into()),
        }
    }

    pub fn by_label(label: impl Into<String>) -> Self {
        Self {
            selector: KeySelector::Label(label.into()),
        }
    }

    pub(crate) fn selector(&self) -> &KeySelector {
        &self.selector
    }
}
