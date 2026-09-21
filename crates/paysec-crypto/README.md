# paysec-crypto

Core cryptographic provider traits used by the `paysec` payment-security
libraries.

This crate defines cryptographic interfaces and common cryptographic types, but
does not provide a cryptographic implementation itself. Concrete providers are
supplied by separate crates such as `paysec-crypto-rustcrypto`,
`paysec-crypto-soft-aes`, and `paysec-crypto-pkcs11`.

## Features

The crate currently provides provider traits for:

* AES block encryption and decryption
* AES-CBC encryption and decryption
* AES-CMAC
* AES-CMAC-based key derivation
* AES-128, AES-192, and AES-256 key-size modeling
* cryptographically secure random-byte generation
* RSAES-OAEP encryption using SHA-256 and MGF1 with SHA-256
* RSASSA-PKCS1-v1_5 signing using SHA-256
* RSASSA-PKCS1-v1_5 signature verification using SHA-256

Provider traits are generic over the key type. This allows software providers
to operate on raw key material while allowing hardware-backed providers to use
opaque key references without exposing persistent secret or private key
material to the application.

Capabilities are exposed as independent traits. A provider only needs to
implement the operations it supports; for example, an AES-only provider does
not need to implement RSA capabilities.

The `AesCmacKeyDerivation` capability also defines a provider-specific derived
key type. Software providers can return owned key material, while an HSM-backed
provider can potentially return an opaque derived-key reference.

Randomness is provider-controlled. This allows software providers to use
operating-system entropy or deterministic entropy sources for testing, while
PKCS #11 or HSM-backed providers can use device-generated randomness.

## Installation

```toml
[dependencies]
paysec-crypto = "0.3.1"
```

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

Concrete implementations are available separately.

### `paysec-crypto-rustcrypto`

Software provider based on the RustCrypto ecosystem.

It provides the broader software-backed capability set, including:

* AES block operations
* AES-CBC
* AES-CMAC
* AES-CMAC-based key derivation
* cryptographic randomness
* RSAES-OAEP-SHA256 encryption
* RSA PKCS#1 v1.5 SHA-256 signing and verification

### `paysec-crypto-soft-aes`

Software provider based on `soft-aes`.

It provides AES capabilities and AES-CMAC-based key derivation, but does not
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
* AES-CBC using temporary PKCS #11 session objects for host-resident ephemeral
  keys

The PKCS #11 provider satisfies the cryptographic capability requirements of
the current TR-34 two-pass key-export API.

It does not currently implement `AesCmacKeyDerivation`, so TR-31 Version D is
not yet supported end-to-end through `paysec-crypto-pkcs11`.

Actual mechanism and parameter support depends on the selected PKCS #11 token
or HSM.

## Provider design

The capability traits intentionally describe cryptographic operations rather
than a specific cryptographic library.

For example:

```rust
AesBlockCipher<K>
AesCbc<K>
AesCmac<K>
AesCmacKeyDerivation<K>

RandomBytes

RsaOaepSha256Encrypt<K>
RsaPkcs1v15Sha256Sign<K>
RsaPkcs1v15Sha256Verify<K>
```

The provider chooses what `K` represents.

For a software implementation, `K` may be raw key bytes. For a PKCS #11
implementation, `K` may instead identify a secret, public, or private key
stored by the token.

This separation allows payment-standard crates to remain independent of
whether cryptographic operations are implemented in software or delegated to
an HSM.

## Security

This crate defines cryptographic interfaces only. Security properties depend
on the concrete provider, its source of randomness, the capabilities of the
underlying cryptographic implementation, and how keys are generated, stored,
provisioned, and managed.

Software providers generally operate on key material in application memory.

An HSM-backed provider can instead operate on opaque key references, but the
provider abstraction itself does not guarantee that a referenced key is
non-exportable or was securely provisioned. Those properties depend on the
underlying device, key attributes, and operational processes.

Applications should select providers and key-management processes appropriate
for their security requirements.

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).
