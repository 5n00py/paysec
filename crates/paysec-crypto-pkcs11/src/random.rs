use paysec_crypto::RandomBytes;

use crate::{Pkcs11Error, Pkcs11Provider};

impl RandomBytes for Pkcs11Provider {
    fn fill_random(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.with_session(|session| {
            session.generate_random_slice(output).map_err(|error| {
                Pkcs11Error::cryptoki("failed to generate PKCS #11 random bytes", error)
            })
        })
    }
}
