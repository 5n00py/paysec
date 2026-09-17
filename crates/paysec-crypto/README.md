# paysec-crypto

Core cryptographic provider traits used by the `paysec` payment-security
libraries.

This crate defines cryptographic interfaces and common cryptographic types, but
does not provide a cryptographic implementation itself. Concrete providers are
supplied by crates such as `paysec-crypto-rustcrypto` and
`paysec-crypto-soft-aes`.

## Features

The crate currently provides provider traits for:

- AES block encryption and decryption
- AES-CBC encryption and decryption
- AES-CMAC
- AES-CMAC-based key derivation
- AES-128, AES-192, and AES-256 key-size modeling
- cryptographically secure random-byte generation
- RSAES-OAEP encryption using SHA-256 and MGF1 with SHA-256
- RSASSA-PKCS1-v1_5 signing using SHA-256
- RSASSA-PKCS1-v1_5 signature verification using SHA-256

Provider traits are generic over the key type. This allows software providers
to operate on raw key material while leaving room for providers backed by
opaque key handles, such as Hardware Security Modules.

Capabilities are exposed as independent traits. A provider only needs to
implement the operations it supports; for example, an AES-only provider does
not need to implement the RSA capabilities.

Randomness is also provider-controlled. This allows software providers to use
operating-system entropy or deterministic entropy sources for testing, while
HSM-backed providers can use device-generated randomness.

## Installation

```toml
[dependencies]
paysec-crypto = "0.3.0"
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

`paysec-crypto-rustcrypto` provides the broader RustCrypto-backed capability
set, including AES and RSA operations.

`paysec-crypto-soft-aes` provides AES capabilities only and is not intended to
implement RSA operations.

## Security

This crate defines cryptographic interfaces only. Security properties depend
on the concrete provider, its source of randomness, and how cryptographic keys
are generated, stored, and managed.

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).
