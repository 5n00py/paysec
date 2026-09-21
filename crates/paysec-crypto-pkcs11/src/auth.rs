use std::fmt::{Debug, Formatter};

use cryptoki::types::AuthPin;

pub struct Pkcs11UserPin {
    pin: AuthPin,
}

impl Pkcs11UserPin {
    pub fn new(pin: impl Into<String>) -> Self {
        let pin = pin.into();

        Self {
            pin: AuthPin::new(pin.into_boxed_str()),
        }
    }

    pub(crate) fn as_auth_pin(&self) -> &AuthPin {
        &self.pin
    }
}

impl Debug for Pkcs11UserPin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pkcs11UserPin([REDACTED])")
    }
}

#[derive(Debug)]
pub enum Pkcs11Auth {
    UserPin(Pkcs11UserPin),
    ProtectedAuthenticationPath,
}

impl Pkcs11Auth {
    pub fn user_pin(pin: impl Into<String>) -> Self {
        Self::UserPin(Pkcs11UserPin::new(pin))
    }

    pub const fn protected_authentication_path() -> Self {
        Self::ProtectedAuthenticationPath
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_pin_debug_is_redacted() {
        let pin = Pkcs11UserPin::new("123456");

        let debug = format!("{pin:?}");

        assert!(!debug.contains("123456"));
        assert!(debug.contains("REDACTED"));
    }
}
