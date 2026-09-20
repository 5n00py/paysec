# paysec-crypto-soft-aes

Software AES cryptographic provider for the `paysec` payment-security
libraries.

This crate implements the provider interfaces defined by `paysec-crypto` using
the `soft-aes` implementation.

## Features

The provider supports the AES operations required by the payment-security
crates in this workspace, including:

- AES block operations
- AES-CBC
- AES-CMAC
- AES-CMAC-based key derivation

The provider operates on raw software key material.

This provider implements the AES capabilities used by the paysec crates.
It does not provide the RSA or randomness capabilities required by
`paysec-tr34`.

## Installation

```toml
[dependencies]
paysec-crypto = "0.3"
paysec-crypto-soft-aes = "0.3"
````

## Usage

```rust
use paysec_crypto::AesBlockCipher;
use paysec_crypto_soft_aes::SoftAesProvider;

let provider = SoftAesProvider::new();

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

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).
