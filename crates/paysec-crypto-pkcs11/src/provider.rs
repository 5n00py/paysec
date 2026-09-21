use std::sync::Mutex;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use paysec_crypto::CryptoProvider;

use crate::{Pkcs11Auth, Pkcs11Config, Pkcs11Error, TokenSelector};

pub struct Pkcs11Provider {
    _pkcs11: Pkcs11,
    slot: Slot,
    session: Mutex<Session>,
}

impl Pkcs11Provider {
    pub fn connect(config: &Pkcs11Config, auth: &Pkcs11Auth) -> Result<Self, Pkcs11Error> {
        let pkcs11 = Pkcs11::new(config.module_path()).map_err(|error| {
            Pkcs11Error::cryptoki(
                format!(
                    "failed to load PKCS #11 module {}",
                    config.module_path().display()
                ),
                error,
            )
        })?;

        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|error| {
                Pkcs11Error::cryptoki("failed to initialize PKCS #11 module", error)
            })?;

        let slot = resolve_slot(&pkcs11, config.token())?;

        if matches!(auth, Pkcs11Auth::ProtectedAuthenticationPath) {
            let token_info = pkcs11.get_token_info(slot).map_err(|error| {
                Pkcs11Error::cryptoki("failed to read PKCS #11 token information", error)
            })?;

            if !token_info.protected_authentication_path() {
                return Err(Pkcs11Error::new(
                    "PKCS #11 token does not support a protected authentication path",
                ));
            }
        }

        let session = pkcs11.open_ro_session(slot).map_err(|error| {
            Pkcs11Error::cryptoki("failed to open PKCS #11 read-only session", error)
        })?;

        match auth {
            Pkcs11Auth::UserPin(pin) => {
                session
                    .login(UserType::User, Some(pin.as_auth_pin()))
                    .map_err(|error| {
                        Pkcs11Error::cryptoki("failed to authenticate PKCS #11 user", error)
                    })?;
            }

            Pkcs11Auth::ProtectedAuthenticationPath => {
                session.login(UserType::User, None).map_err(|error| {
                    Pkcs11Error::cryptoki(
                        "failed to authenticate using protected authentication path",
                        error,
                    )
                })?;
            }
        }

        Ok(Self {
            _pkcs11: pkcs11,
            slot,
            session: Mutex::new(session),
        })
    }

    pub fn slot_id(&self) -> u64 {
        self.slot.id()
    }

    pub(crate) fn with_session<T>(
        &self,
        operation: impl FnOnce(&Session) -> Result<T, Pkcs11Error>,
    ) -> Result<T, Pkcs11Error> {
        let session = self
            .session
            .lock()
            .map_err(|_| Pkcs11Error::new("PKCS #11 session lock poisoned"))?;

        operation(&session)
    }
}

impl CryptoProvider for Pkcs11Provider {
    type Error = Pkcs11Error;
}

fn resolve_slot(pkcs11: &Pkcs11, selector: &TokenSelector) -> Result<Slot, Pkcs11Error> {
    let slots = pkcs11.get_slots_with_initialized_token().map_err(|error| {
        Pkcs11Error::cryptoki("failed to enumerate initialized PKCS #11 tokens", error)
    })?;

    match selector {
        TokenSelector::SlotId(slot_id) => slots
            .into_iter()
            .find(|slot| slot.id() == *slot_id)
            .ok_or_else(|| {
                Pkcs11Error::new(format!(
                    "no initialized PKCS #11 token found in slot {slot_id}"
                ))
            }),

        TokenSelector::Label(label) => {
            let mut matches = Vec::new();

            for slot in slots {
                let token_info = pkcs11.get_token_info(slot).map_err(|error| {
                    Pkcs11Error::cryptoki(
                        format!(
                            "failed to read PKCS #11 token information for slot {}",
                            slot.id()
                        ),
                        error,
                    )
                })?;

                if token_info.label() == label {
                    matches.push(slot);
                }
            }

            match matches.as_slice() {
                [] => Err(Pkcs11Error::new(format!(
                    "no initialized PKCS #11 token found with label {label:?}"
                ))),

                [slot] => Ok(*slot),

                _ => Err(Pkcs11Error::new(format!(
                    "multiple initialized PKCS #11 tokens found with label {label:?}"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn provider_is_send_and_sync() {
        assert_send_sync::<Pkcs11Provider>();
    }
}
