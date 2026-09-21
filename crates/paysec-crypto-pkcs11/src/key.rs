#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySelector {
    Id(Vec<u8>),
    Label(String),
}

impl KeySelector {
    pub fn id(id: impl Into<Vec<u8>>) -> Self {
        Self::Id(id.into())
    }

    pub fn label(label: impl Into<String>) -> Self {
        Self::Label(label.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11Key {
    selector: KeySelector,
}

impl Pkcs11Key {
    pub fn new(selector: KeySelector) -> Self {
        Self { selector }
    }

    pub fn by_id(id: impl Into<Vec<u8>>) -> Self {
        Self::new(KeySelector::id(id))
    }

    pub fn by_label(label: impl Into<String>) -> Self {
        Self::new(KeySelector::label(label))
    }

    pub fn selector(&self) -> &KeySelector {
        &self.selector
    }
}
