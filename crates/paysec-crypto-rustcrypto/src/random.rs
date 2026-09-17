use paysec_crypto::RandomBytes;
use rand_core::{CryptoRng, OsRng, RngCore};

use crate::{RustCryptoError, RustCryptoProvider, RustCryptoProviderWithRng};

impl RandomBytes for RustCryptoProvider {
    fn fill_random(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        let mut rng = OsRng;

        rng.try_fill_bytes(output)
            .map_err(|_| RustCryptoError::random_generation_failed())
    }
}

impl<R> RandomBytes for RustCryptoProviderWithRng<R>
where
    R: RngCore + CryptoRng,
{
    fn fill_random(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.rng_mut()
            .try_fill_bytes(output)
            .map_err(|_| RustCryptoError::random_generation_failed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl FixedRng {
        fn new(bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                bytes: bytes.into(),
                offset: 0,
            }
        }
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.offset + dest.len();

            assert!(end <= self.bytes.len(), "fixed RNG exhausted");

            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}

    #[test]
    fn injected_rng_produces_expected_bytes() {
        let rng = FixedRng::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);

        let mut provider = RustCryptoProvider::with_rng(rng);

        let mut output = [0u8; 16];
        provider.fill_random(&mut output).unwrap();

        assert_eq!(
            output,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
    }
}
