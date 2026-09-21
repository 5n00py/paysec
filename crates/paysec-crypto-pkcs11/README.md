# paysec-crypto-pkcs11

PKCS #11-backed cryptographic provider for the `paysec` payment-security
libraries.

The provider implements cryptographic interfaces defined by `paysec-crypto`
using an existing PKCS #11 token, such as a Hardware Security Module (HSM) or
a software implementation such as SoftHSM2.

Unlike the software providers, cryptographic keys are represented by opaque
`Pkcs11Key` references. Key material does not need to be supplied to the
application in order to perform supported cryptographic operations.

## Features

The provider currently supports:

* AES block encryption and decryption
* AES-CBC encryption and decryption without padding
* AES-CMAC
* RSAES-OAEP encryption using SHA-256 and MGF1 with SHA-256
* RSASSA-PKCS1-v1_5 signing using SHA-256
* RSASSA-PKCS1-v1_5 signature verification using SHA-256

The corresponding PKCS #11 mechanisms are:

```text
paysec-crypto capability          PKCS #11 mechanism
----------------------------------------------------------------
AES block operations             CKM_AES_ECB
AES-CBC                          CKM_AES_CBC
AES-CMAC                         CKM_AES_CMAC
RSAES-OAEP SHA-256               CKM_RSA_PKCS_OAEP
RSASSA-PKCS1-v1_5 SHA-256        CKM_SHA256_RSA_PKCS
```

`CKM_AES_ECB` is used only to implement the single-block AES primitive
exposed by `AesBlockCipher`. This crate does not expose a general-purpose
ECB mode API.

Mechanism support ultimately depends on the selected PKCS #11 token. A
capability implemented by this crate can only be used when the underlying
token supports the required mechanism and parameters.

## Installation

```toml
[dependencies]
paysec-crypto = "0.3"
paysec-crypto-pkcs11 = "0.1"
```

## Usage

The provider connects to an already initialized PKCS #11 token.

```rust
use paysec_crypto::AesBlockCipher;
use paysec_crypto_pkcs11::{
    Pkcs11Auth,
    Pkcs11Config,
    Pkcs11Key,
    Pkcs11Provider,
    TokenSelector,
};

let config = Pkcs11Config::new(
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    TokenSelector::label("paysec"),
);

let auth = Pkcs11Auth::user_pin("123456");

let provider = Pkcs11Provider::connect(&config, &auth)?;

let key = Pkcs11Key::by_id([0x10]);

let block = [0u8; 16];

let encrypted = provider.encrypt_block(&key, &block)?;

assert_eq!(encrypted.len(), 16);

# Ok::<(), paysec_crypto_pkcs11::Pkcs11Error>(())
```

Applications are responsible for obtaining module paths, token selectors, and
authentication credentials from an appropriate configuration source. The
provider itself does not depend on environment-variable based configuration.

## PKCS #11 keys

`Pkcs11Key` identifies an existing PKCS #11 key object without exposing an
`ObjectHandle` or the key material itself.

Keys can currently be selected by object ID:

```rust
use paysec_crypto_pkcs11::Pkcs11Key;

let key = Pkcs11Key::by_id([0x20]);
```

or by label:

```rust
use paysec_crypto_pkcs11::Pkcs11Key;

let key = Pkcs11Key::by_label("payment-key");
```

Object IDs should generally be preferred when available. PKCS #11 object
labels are convenient identifiers but are not required to be unique.

The provider resolves the key reference within the active session and also
constrains the lookup by the object class and key type required by the
cryptographic operation.

For an RSA key pair, the public and private objects can therefore share the
same logical `Pkcs11Key` identifier:

```text
RSA encryption / verification -> public key object
RSA signing                    -> private key object
```

The resulting PKCS #11 object handle remains internal to the provider.

## Authentication

User authentication is separate from non-secret provider configuration.

A user PIN can be supplied with:

```rust
use paysec_crypto_pkcs11::Pkcs11Auth;

let auth = Pkcs11Auth::user_pin("123456");
```

The PIN is used to authenticate the PKCS #11 session and is not retained by
`Pkcs11Provider` after connection.

Tokens supporting a protected authentication path can instead use:

```rust
use paysec_crypto_pkcs11::Pkcs11Auth;

let auth = Pkcs11Auth::protected_authentication_path();
```

The provider checks that the token advertises protected-authentication-path
support before attempting this form of login.

## Token and key provisioning

This crate intentionally does not provide PKCS #11 administration or key
provisioning APIs.

In particular, `Pkcs11Provider` does not:

* initialize tokens
* set or change PINs
* generate keys
* import keys
* modify key attributes
* delete keys

The provider opens a read-only session and operates on existing key objects.

This reflects deployments where application credentials are permitted to use
cryptographic keys but are not permitted to create, import, modify, or destroy
them. Token initialization and key provisioning should be handled by the
appropriate operational or administrative process.

The required PKCS #11 attributes, including cryptographic usage permissions,
must be assigned when the key is provisioned.

## Session model

`Pkcs11Provider` owns the PKCS #11 context, selected slot, and authenticated
session.

A provider instance can be shared between callers. Cryptographic operations
currently serialize access through a single PKCS #11 session.

This is intentionally a simple initial session model. Applications should not
rely on the internal session-management strategy; it may evolve without
changing the provider or `Pkcs11Key` APIs.

## RSA

RSA-OAEP encryption uses the fixed profile exposed by `paysec-crypto`:

* SHA-256 as the OAEP hash
* MGF1 with SHA-256
* an empty OAEP label

RSASSA-PKCS1-v1_5 signing and verification use SHA-256.

### SoftHSM and RSA-OAEP-SHA256

The SoftHSM implementation used by this project's integration-test
environment does not support the SHA-256/MGF1-SHA256 parameter profile for
`CKM_RSA_PKCS_OAEP`.

For that reason, `RsaOaepSha256Encrypt` is implemented by this provider but
is not currently exercised by the SoftHSM integration suite.

The implementation is not weakened to SHA-1 to accommodate SoftHSM because
that would violate the `RsaOaepSha256Encrypt` contract defined by
`paysec-crypto`.

RSA PKCS#1 v1.5 SHA-256 signing and verification are exercised against
SoftHSM.

## DUKPT

Full DUKPT derivation is not currently supported by this provider.

The current `paysec-crypto` DUKPT flow performs subsequent AES operations on
derived software key material. `Pkcs11Provider` intentionally implements AES
operations for opaque `Pkcs11Key` objects and does not provide software AES
operations over raw `[u8]` keys.

Supporting HSM-contained DUKPT derivation would require a different
abstraction for derived opaque keys and is outside the scope of this provider.

## Integration tests

The crate includes opt-in integration tests against SoftHSM2.

The tests cover:

* AES block encryption and decryption using a known-answer vector
* AES-CBC using a multi-block known-answer vector
* AES-CMAC using an RFC 4493 known-answer vector
* missing-key handling
* rejection of non-block-aligned AES-CBC input
* RSA PKCS#1 v1.5 SHA-256 signing and verification
* rejection of a signature when the signed message is modified

The SoftHSM tests require an externally initialized token with pre-provisioned
test keys and are therefore ignored during a normal `cargo test` run.

See [`tests/README.md`](tests/README.md) for the test-token setup and
provisioning instructions.

## Security

`Pkcs11Provider` performs cryptographic operations through the selected
PKCS #11 token. It does not read secret or private key values as part of its
cryptographic operations.

Whether a key is actually non-exportable depends on the PKCS #11 token, the
key's attributes, and the process by which the key was provisioned. Using
`Pkcs11Provider` alone does not guarantee that a key was generated securely or
configured as non-extractable.

Authentication credentials should be obtained and protected using mechanisms
appropriate to the application and HSM deployment.

The provider preserves errors returned by the PKCS #11 implementation where
possible. Device-specific mechanism restrictions and key-usage policies may
therefore cause operations to fail even when the corresponding capability is
implemented by this crate.

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).
