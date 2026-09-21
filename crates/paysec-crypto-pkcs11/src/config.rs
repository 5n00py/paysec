use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSelector {
    Label(String),
    SlotId(u64),
}

impl TokenSelector {
    pub fn label(label: impl Into<String>) -> Self {
        Self::Label(label.into())
    }

    pub const fn slot_id(slot_id: u64) -> Self {
        Self::SlotId(slot_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11Config {
    module_path: PathBuf,
    token: TokenSelector,
}

impl Pkcs11Config {
    pub fn new(module_path: impl Into<PathBuf>, token: TokenSelector) -> Self {
        Self {
            module_path: module_path.into(),
            token,
        }
    }

    pub fn module_path(&self) -> &Path {
        &self.module_path
    }

    pub fn token(&self) -> &TokenSelector {
        &self.token
    }
}
