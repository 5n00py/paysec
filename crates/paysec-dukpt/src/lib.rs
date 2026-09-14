//! AES DUKPT key derivation according to ANSI X9.24-3.
//!
//! This crate currently focuses on receiving-side / host key derivation.

mod derivation;
mod error;
mod initial_key_id;
mod secret;

pub use derivation::derive_initial_key;
pub use error::DukptError;
pub use initial_key_id::InitialKeyId;
pub use secret::DukptKey;
