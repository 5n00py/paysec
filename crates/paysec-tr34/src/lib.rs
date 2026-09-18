//! ASC X9 TR-34 key transport support for payment security applications.
//!
//! This crate currently provides KDH-side two-pass key export using a
//! provider-neutral cryptographic interface.
//!
//! The high-level API emits the complete DER-encoded TR-34 key token.
//! Certificate-path, revocation, validity, and profile validation remain
//! the responsibility of the application unless explicitly documented
//! otherwise.

mod asn1;
mod credential;
mod crl;
mod error;
mod kdh;
mod oid;

pub use credential::{KdhCredential, KrdCredential};

pub use crl::KdhCrl;

pub use error::{Tr34CryptoError, Tr34Error};

pub use kdh::{TwoPassKeyExportRequest, export_key_two_pass};
