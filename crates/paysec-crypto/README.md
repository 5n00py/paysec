# paysec-crypto

Core cryptographic provider traits used by the `paysec` payment-security
libraries.

This crate defines cryptographic interfaces and common AES types, but does not
provide a cryptographic implementation itself. Concrete providers are supplied
by crates such as `paysec-crypto-rustcrypto` and `paysec-crypto-soft-aes`.

## Features

The crate currently provides provider traits for:

- AES block encryption and decryption
- AES-CBC encryption and decryption
- AES-CMAC
- AES-CMAC-based key derivation
- AES-128, AES-192, and AES-256 key-size modeling

Provider traits are generic over the key type. This allows software providers
to operate on raw key material while leaving room for providers backed by
opaque key handles, such as Hardware Security Modules.

## Installation

```toml
[dependencies]
paysec-crypto = "0.2.0"
````

## Example

```rust
use paysec_crypto::{AesBlockCipher, AesKeySize};

fn key_length(key_size: AesKeySize) -> usize {
    key_size.bytes()
}

assert_eq!(key_length(AesKeySize::Bits128), 16);
assert_eq!(key_length(AesKeySize::Bits256), 32);
```

## Implementations

Software implementations are available separately:

* `paysec-crypto-rustcrypto`
* `paysec-crypto-soft-aes`

## Security

This crate defines cryptographic interfaces only. Security properties depend
on the concrete provider and on how keys are stored and managed.

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).

