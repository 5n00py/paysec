use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct Pkcs11Error {
    message: String,
    source: Option<cryptoki::error::Error>,
}

impl Pkcs11Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn cryptoki(message: impl Into<String>, source: cryptoki::error::Error) -> Self {
        Self {
            message: message.into(),
            source: Some(source),
        }
    }
}

impl Display for Pkcs11Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;

        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }

        Ok(())
    }
}

impl Error for Pkcs11Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}
