# paysec-crypto-rustcrypto

RustCrypto-based cryptographic provider for the `paysec` payment-security
libraries.

The provider implements the interfaces defined by `paysec-crypto` using
RustCrypto crates.

## Features

The provider currently supports:

- AES-128, AES-192, and AES-256 block operations
- AES-CBC without padding
- AES-CMAC
- AES-CMAC-based key derivation

The provider operates on raw software key material.

## Installation

```toml
[dependencies]
paysec-crypto = "0.2.0"
paysec-crypto-rustcrypto = "0.2.0"
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

## Security

Keys supplied to this provider are present as plaintext software key material
in process memory.

Applications requiring non-exportable keys or HSM-backed key management should
use an appropriate cryptographic provider when one is available.

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).

