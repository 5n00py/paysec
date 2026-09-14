# paysec

Convenience facade for the `paysec` payment-security crates.

`paysec` provides a single entry point for the project's high-level
payment-security functionality while keeping cryptographic provider
implementations as explicit dependencies.

## Modules

The facade currently exposes:

- `paysec::dukpt`
  - ANSI X9.24-3 AES DUKPT
  - host / receiving-side derivation
  - native 96-bit KSNs
  - Initial Keys, transaction working keys, and Update Keys

- `paysec::keyblock`
  - ASC X9 TR-31 key blocks
  - Version D wrapping and unwrapping
  - headers and optional blocks

- `paysec::pinblock`
  - ISO 9564 PIN blocks
  - Format 3
  - Format 4 with AES protection

The underlying crates remain independently versioned and can also be used
directly.

## Installation

```toml
[dependencies]
paysec = "0.3"
````

Operations that perform cryptography also require a provider. For example,
using the RustCrypto-based provider:

```toml
[dependencies]
paysec = "0.3"
paysec-crypto = "0.2.1"
paysec-crypto-rustcrypto = "0.2.1"
```

The `paysec-crypto` dependency is useful for common cryptographic types such
as `AesKeySize`, while `paysec-crypto-rustcrypto` supplies the concrete
provider.

## AES DUKPT example

The following example derives an AES-128 PIN working key from a Base
Derivation Key and native 96-bit AES DUKPT Key Serial Number:

```rust
use paysec::dukpt::{
    derive_working_key,
    KeySerialNumber,
    WorkingKeyUsage,
};

use paysec_crypto::AesKeySize;
use paysec_crypto_rustcrypto::RustCryptoProvider;

let provider = RustCryptoProvider::new();

let bdk = hex::decode(
    "FEDCBA9876543210F1F1F1F1F1F1F1F1",
)
.unwrap();

let ksn = KeySerialNumber::from_parts(
    0x12345678,
    0x90123456,
    0x0000_0001,
);

let working_key = derive_working_key(
    &provider,
    bdk.as_slice(),
    AesKeySize::Bits128,
    WorkingKeyUsage::PinEncryption,
    AesKeySize::Bits128,
    ksn,
)
.unwrap();

assert_eq!(
    hex::encode_upper(
        working_key.expose_secret(),
    ),
    "AF8CB133A78F8DC2D1359F18527593FB",
);
```

To run the example exactly as written, add:

```toml
hex = "0.4"
```

## Direct crate usage

Applications can also depend directly on the focused crates:

```toml
[dependencies]
paysec-dukpt = "0.1"
paysec-keyblock = "0.2.1"
paysec-pinblock = "0.2.1"
```

See their individual documentation for detailed functionality and examples:

* [`paysec-dukpt`](../paysec-dukpt/README.md)
* [`paysec-keyblock`](../paysec-keyblock/README.md)
* [`paysec-pinblock`](../paysec-pinblock/README.md)

## Cryptographic providers

The facade does not select or bundle a cryptographic implementation.

Cryptographic operations are delegated through the provider traits defined by
`paysec-crypto`. Current software implementations include:

* `paysec-crypto-rustcrypto`
* `paysec-crypto-soft-aes`

This keeps payment-standard functionality separate from the chosen
cryptographic backend.

## Security

The software providers operate on key material in application memory and do
not provide the isolation or non-exportability guarantees of a Hardware
Security Module.

The payment-security crates use dedicated secret types where appropriate,
including redacted debug output and zeroization of owned secret material.

Using this library does not by itself establish compliance with PCI, ANSI,
ISO, or other payment-security requirements.

For the complete project overview, see the
[`paysec` repository](https://github.com/5n00py/paysec).

## License

`paysec` is licensed under the GNU General Public License Version 3.0
(`GPL-3.0`).

See the repository `LICENSE` file for the complete license terms.
