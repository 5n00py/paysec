# paysec-crypto-rustcrypto

RustCrypto-based cryptographic provider for the `paysec` payment-security
libraries.

The provider implements cryptographic interfaces defined by `paysec-crypto`
using RustCrypto crates.

## Features

The provider currently supports:

- AES-128, AES-192, and AES-256 block operations
- AES-CBC without padding
- AES-CMAC
- AES-CMAC-based key derivation
- cryptographically secure random-byte generation
- RSAES-OAEP encryption using SHA-256 and MGF1 with SHA-256
- RSASSA-PKCS1-v1_5 signing using SHA-256
- RSASSA-PKCS1-v1_5 signature verification using SHA-256

AES operations use raw software key material. RSA operations use RustCrypto
`RsaPublicKey` and `RsaPrivateKey` values.

Two provider variants are available.

`RustCryptoProvider` uses operating-system randomness for operations requiring
randomness.

`RustCryptoProviderWithRng<R>` uses a caller-supplied cryptographically secure
random number generator. This allows applications to control the entropy source
and enables deterministic conformance and test-vector generation when used with
an appropriate test RNG.

RSA-OAEP randomness is controlled by the provider. The caller does not supply
an OAEP seed directly.

## Installation

```toml
[dependencies]
paysec-crypto = "0.3.0"
paysec-crypto-rustcrypto = "0.3.0"
````

## Example

```rust
use paysec_crypto::AesBlockCipher;
use paysec_crypto_rustcrypto::RustCryptoProvider;

let provider = RustCryptoProvider::new();

let key = [0u8; 16];
let block = [0u8; 16];

let encrypted = provider
    .encrypt_block(&key[..], &block)
    .unwrap();

assert_eq!(encrypted.len(), 16);
```

Randomized operations can use the default provider:

```rust
use paysec_crypto::RandomBytes;
use paysec_crypto_rustcrypto::RustCryptoProvider;

let mut provider = RustCryptoProvider::new();

let mut bytes = [0u8; 16];
provider.fill_random(&mut bytes).unwrap();
```

A caller-supplied random number generator can be used when the entropy source
must be controlled:

```rust
use paysec_crypto_rustcrypto::RustCryptoProvider;

let provider = RustCryptoProvider::with_rng(my_rng);
```

The supplied RNG must satisfy the RustCrypto cryptographic RNG requirements.

## RSA

RustCrypto RSA key types are re-exported by this crate:

```rust
use paysec_crypto_rustcrypto::{
    RsaPrivateKey,
    RsaPublicKey,
};
```

RSA-OAEP encryption uses the fixed profile exposed by `paysec-crypto`:

* SHA-256 as the OAEP hash
* MGF1 with SHA-256
* an empty OAEP label

PKCS#1 v1.5 signatures use SHA-256.

## Security

Keys supplied to this provider are present as software key material in process
memory. This includes AES keys and RSA private keys.

`RustCryptoProvider` obtains randomness from the operating system.
`RustCryptoProviderWithRng<R>` relies on the supplied RNG, which must provide
cryptographically secure and unpredictable randomness in production.

Deterministic RNGs are useful for tests and conformance vectors but must not be
used in production.

Applications requiring non-exportable keys or HSM-backed key management should
use an appropriate cryptographic provider when one is available.

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).
