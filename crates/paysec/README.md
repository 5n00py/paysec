# paysec

Convenience facade for the `paysec` payment-security crates.

`paysec` provides a single entry point for the project's high-level
payment-security functionality while keeping cryptographic provider
implementations as explicit dependencies.

## Modules

The facade currently exposes:

* `paysec::dukpt`

  * ANSI X9.24-3 AES DUKPT
  * host / receiving-side derivation
  * native 96-bit KSNs
  * Initial Keys, transaction working keys, and Update Keys

* `paysec::keyblock`

  * ASC X9 TR-31 key blocks
  * Version D wrapping and unwrapping
  * headers and optional blocks

* `paysec::pinblock`

  * ISO 9564 PIN blocks
  * Format 3
  * Format 4 with AES protection

* `paysec::tr34`

  * ASC X9 TR-34 key transport
  * KDH-side two-pass AES key export
  * strict CMS encoding
  * TR-34 2019 Annex B interoperability profile

The underlying crates remain independently versioned and can also be used
directly.

## Installation

```toml
[dependencies]
paysec = "0.4.1"
```

Operations that perform cryptography also require a provider.

For example, using the RustCrypto-based software provider:

```toml
[dependencies]
paysec = "0.4.1"
paysec-crypto = "0.3.1"
paysec-crypto-rustcrypto = "0.3"
```

Or using a PKCS #11-backed provider:

```toml
[dependencies]
paysec = "0.4.1"
paysec-crypto = "0.3.1"
paysec-crypto-pkcs11 = "0.1"
```

The `paysec-crypto` dependency provides common cryptographic types such as
`AesKeySize`, while the selected provider crate supplies the concrete
implementation.

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
paysec-dukpt = "0.2"
paysec-keyblock = "0.3"
paysec-pinblock = "0.3"
paysec-tr34 = "0.1"
```

See their individual documentation for detailed functionality and examples:

* [`paysec-dukpt`](../paysec-dukpt/README.md)
* [`paysec-keyblock`](../paysec-keyblock/README.md)
* [`paysec-pinblock`](../paysec-pinblock/README.md)
* [`paysec-tr34`](../paysec-tr34/README.md)

## Cryptographic providers

The facade does not select or bundle a cryptographic implementation.

Cryptographic operations are delegated through the capability traits defined
by `paysec-crypto`.

The project currently provides three concrete providers:

### `paysec-crypto-rustcrypto`

Software provider based on the RustCrypto ecosystem.

It provides:

* AES block operations
* AES-CBC
* AES-CMAC
* AES-CMAC-based key derivation
* cryptographic randomness
* RSAES-OAEP-SHA256 encryption
* RSA PKCS#1 v1.5 SHA-256 signing and verification

It supports the capabilities currently required by TR-34 and TR-31.

### `paysec-crypto-soft-aes`

Software provider based on `soft-aes`.

It provides AES operations and AES-CMAC-based key derivation, but does not
provide the RSA or randomness capabilities required by TR-34.

### `paysec-crypto-pkcs11`

PKCS #11 provider for Hardware Security Modules and compatible software tokens.

It can perform supported operations using opaque `Pkcs11Key` references to
existing PKCS #11 objects and provides:

* AES block operations
* AES-CBC
* AES-CMAC
* token-backed cryptographic randomness
* RSAES-OAEP-SHA256 encryption
* RSA PKCS#1 v1.5 SHA-256 signing and verification
* AES-CBC over host-resident ephemeral keys through temporary,
  non-persistent PKCS #11 session objects

The provider satisfies the cryptographic capability requirements of the
current TR-34 two-pass key-export API.

It does not currently implement `AesCmacKeyDerivation`, so TR-31 Version D is
not yet supported end-to-end through `paysec-crypto-pkcs11`.

Full HSM-contained AES DUKPT derivation is also not currently supported.

Actual PKCS #11 mechanism and parameter support depends on the selected token
or HSM.

## Security

The software providers operate on key material in application memory and do
not provide the isolation or non-exportability guarantees of a Hardware
Security Module.

`paysec-crypto-pkcs11` can instead perform supported cryptographic operations
using persistent secret and private keys through opaque PKCS #11 references,
without reading their key values into the application.

Whether a PKCS #11 key is actually non-exportable depends on the token, its
attributes, and the provisioning process. Use of `Pkcs11Provider` alone does
not guarantee that a key was securely generated or configured as
non-extractable.

Some protocols deliberately use ephemeral key material in application memory.
For example, the current TR-34 implementation generates an ephemeral AES key
through the selected cryptographic provider. With `Pkcs11Provider`, that key
is imported only as a temporary PKCS #11 session object for the required AES
operation and is destroyed afterward.

The payment-security crates use dedicated secret types where appropriate,
including redacted debug output and zeroization of owned secret material.

These protections are defense in depth and do not guarantee that secret values
have never existed elsewhere in process memory.

Using this library does not by itself establish compliance with PCI, ANSI,
ISO, or other payment-security requirements.

For the complete project overview, see the
[`paysec` repository](https://github.com/5n00py/paysec).

## License

`paysec` is licensed under the GNU General Public License Version 3.0 only
(`GPL-3.0-only`).

See the repository `LICENSE` file for the complete license terms.
