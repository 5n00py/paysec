use paysec_crypto_pkcs11::{Pkcs11Key, Pkcs11Provider};
use paysec_tr34::{Tr34CryptoError, TwoPassKeyExportRequest, export_key_two_pass};

#[allow(dead_code)]
fn export_tr34_with_pkcs11(
    provider: &mut Pkcs11Provider,
    request: TwoPassKeyExportRequest<'_>,
    krd_public_key: &Pkcs11Key,
    kdh_signing_key: &Pkcs11Key,
) -> Result<Vec<u8>, Tr34CryptoError<<Pkcs11Provider as paysec_crypto::CryptoProvider>::Error>> {
    export_key_two_pass(provider, request, krd_public_key, kdh_signing_key)
}
