# paysec

`paysec` is a Rust project for implementing, testing, and working with
payment-security standards used in retail payment systems.

The project provides standards-oriented building blocks for payment
cryptography, including PIN blocks, TR-31 symmetric key blocks, AES DUKPT key
derivation, and TR-34 asymmetric key transport.

Payment-standard logic is separated from cryptographic implementations through
provider traits, allowing applications to select the cryptographic backend
appropriate for their environment.

## Current Status

`paysec` is under active development and currently requires **Rust 1.89 or
newer**.

Implemented functionality includes:

* **ANSI X9.24-3 AES DUKPT**

  * receiving-side / host key derivation
  * native 96-bit AES Key Serial Numbers
  * AES-128, AES-192, and AES-256
  * Initial Key derivation
  * transaction working-key derivation
  * DUKPT Update Key derivation

* **ASC X9 TR-31-2018**

  * key block Version `D`
  * AES-based key block protection
  * key wrapping and unwrapping
  * key block headers and optional blocks
  * KBEK and KBAK derivation using AES-CMAC

* **ISO 9564 PIN blocks**

  * Format 3 encoding and decoding
  * Format 4 encoding and decoding
  * AES-based Format 4 enciphering and deciphering
  * PIN and PAN processing

* **ASC X9 TR-34-2019**

  * KDH-side two-pass symmetric key export
  * AES-128-CBC key transport
  * RSAES-OAEP-SHA256 ephemeral-key protection
  * RSA PKCS#1 v1.5 SHA-256 signatures
  * strict CMS-oriented encoding
  * TR-34 2019 Annex B interoperability profile
  * provider-neutral cryptographic operations

## Workspace

The project is organized as independently versioned Cargo crates.

| Crate                                                                   | Version | Purpose                                               |
| ----------------------------------------------------------------------- |---------| ----------------------------------------------------- |
| [`paysec`](crates/paysec/README.md)                                     | `0.4.1` | Convenience facade for payment-security functionality |
| [`paysec-dukpt`](crates/paysec-dukpt/README.md)                         | `0.2.0` | ANSI X9.24-3 AES DUKPT host-side key derivation       |
| [`paysec-keyblock`](crates/paysec-keyblock/README.md)                   | `0.3.0` | TR-31 key block processing                            |
| [`paysec-pinblock`](crates/paysec-pinblock/README.md)                   | `0.3.1` | ISO 9564 PIN block processing                         |
| [`paysec-tr34`](crates/paysec-tr34/README.md)                           | `0.1.1` | TR-34 KDH-side two-pass AES key transport             |
| [`paysec-crypto`](crates/paysec-crypto/README.md)                       | `0.3.1` | Provider-independent cryptographic capability traits  |
| [`paysec-crypto-rustcrypto`](crates/paysec-crypto-rustcrypto/README.md) | `0.3.0` | RustCrypto-based software provider                    |
| [`paysec-crypto-soft-aes`](crates/paysec-crypto-soft-aes/README.md)     | `0.3.0` | `soft-aes` based AES software provider                |
| [`paysec-crypto-pkcs11`](crates/paysec-crypto-pkcs11/README.md)         | `0.1.0` | PKCS #11 provider for HSMs and compatible tokens      |

Each crate README contains its supported functionality, installation
instructions, examples, and crate-specific security considerations.

## Facade

The `paysec` crate exposes the high-level payment-security crates through:

```rust
paysec::dukpt
paysec::keyblock
paysec::pinblock
paysec::tr34
```

Cryptographic providers remain separate dependencies so applications can
explicitly select the backend appropriate for their environment.

## Architecture

Payment-standard processing is kept separate from cryptographic
implementations.

The `paysec-crypto` crate defines provider traits for capabilities such as:

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

The key type is provider-specific. Software providers can operate on raw key
material, while providers such as `paysec-crypto-pkcs11` can operate on opaque
key references without exposing persistent secret or private key material to
the application.

Three cryptographic providers are currently included:

* `RustCryptoProvider`

  * AES operations
  * AES-CMAC and AES-based key derivation
  * RSA encryption and signatures
  * cryptographic randomness
  * supports the capabilities currently required by TR-34

* `SoftAesProvider`

  * AES operations
  * AES-CMAC and AES-based key derivation
  * does not provide the RSA or randomness capabilities required by TR-34

* `Pkcs11Provider`

  * operates on existing PKCS #11 key objects through opaque `Pkcs11Key`
    references
  * AES block, AES-CBC, and AES-CMAC operations
  * token-backed cryptographic randomness
  * RSAES-OAEP-SHA256 encryption
  * RSA PKCS#1 v1.5 SHA-256 signing and verification
  * supports temporary non-persistent AES session objects for ephemeral
    host-resident keys
  * satisfies the cryptographic provider requirements of the current TR-34
    two-pass key-export API
  * does not currently support TR-31 AES-CMAC key derivation or full
    HSM-contained DUKPT derivation

PKCS #11 mechanism support and parameter profiles ultimately depend on the
selected HSM or token.

## Installation

For the facade crate:

```toml
[dependencies]
paysec = "0.4"
```

Cryptographic operations also require a provider. For example, using the
RustCrypto software provider:

```toml
[dependencies]
paysec = "0.4"
paysec-crypto = "0.3"
paysec-crypto-rustcrypto = "0.3"
```

Or using a PKCS #11-backed provider:

```toml
[dependencies]
paysec = "0.4"
paysec-crypto = "0.3"
paysec-crypto-pkcs11 = "0.1"
```

Applications can also depend directly on individual crates:

```toml
[dependencies]
paysec-dukpt = "0.2"
paysec-keyblock = "0.3"
paysec-pinblock = "0.3"
paysec-tr34 = "0.1"

paysec-crypto = "0.3"
paysec-crypto-rustcrypto = "0.3"
paysec-crypto-pkcs11 = "0.1"
```

See the individual crate READMEs for detailed usage examples and
provider-specific requirements.

## Security

The software providers included in this repository operate on key material in
application memory. They are suitable for development, interoperability work,
standard test vectors, and environments where software-managed keys are
appropriate.

They do not provide the isolation or non-exportability guarantees of a
Hardware Security Module.

`paysec-crypto-pkcs11` instead performs supported cryptographic operations
through an existing PKCS #11 token and can use persistent secret and private
keys through opaque references without reading their key values into the
application.

Whether a PKCS #11 key is actually non-exportable depends on the token, the
key's attributes, and the provisioning process. Use of `Pkcs11Provider` alone
does not establish that a key was securely generated or configured as
non-extractable.

Some protocols deliberately use ephemeral key material in application memory.
For example, the current TR-34 implementation generates an ephemeral AES key
through the selected cryptographic provider. When used with
`Pkcs11Provider`, this host-resident key is imported only as a temporary
non-persistent PKCS #11 session object for the required AES operation and is
destroyed afterward.

The payment-standard crates use dedicated secret types where appropriate.
These types redact secret values from debug output and zeroize owned secret
memory when dropped.

These protections are defense in depth and do not guarantee that secret values
have never existed elsewhere in process memory.

Some operations, such as TR-31 wrapping and ISO 9564 Format 4 PIN-block
construction, accept caller-supplied random data. TR-34 obtains the randomness
required for ephemeral keys, initialization vectors, and RSAES-OAEP through
the selected cryptographic provider.

Applications remain responsible for selecting entropy sources, cryptographic
providers, token configurations, and key-management processes appropriate for
their security requirements.

TR-34 credential parsing does not by itself establish trust. Applications
remain responsible for certificate-path validation, certificate and CRL
validity and freshness, revocation checks, key usage, and other PKI policy
required by their environment.

Using this library does not by itself establish compliance with PCI, ANSI, ISO,
or other payment-security requirements. Production environments may require
additional controls such as certified HSMs, access control, audit logging,
secure key ceremonies, key lifecycle management, and platform hardening.

## Development

The workspace targets:

```text
Rust edition: 2024
MSRV:         1.89
```

Check the complete workspace:

```bash
cargo check --workspace --locked
```

Run the test suite:

```bash
cargo test --workspace --locked
```

Run documentation tests:

```bash
cargo test --workspace --doc --locked
```

Generate API documentation locally:

```bash
cargo doc --workspace --no-deps --locked --open
```

### PKCS #11 integration tests

The `paysec-crypto-pkcs11` crate includes opt-in integration tests against
SoftHSM2. These tests require a separately initialized and provisioned test
token and are ignored during a normal workspace test run.

After preparing the SoftHSM test environment, run them explicitly with:

```bash
cargo test \
    -p paysec-crypto-pkcs11 \
    --test softhsm \
    -- --ignored --test-threads=1
```

See
[`crates/paysec-crypto-pkcs11/tests/README.md`](crates/paysec-crypto-pkcs11/tests/README.md)
for setup and provisioning instructions.

SoftHSM does not currently support the RSA-OAEP SHA-256/MGF1-SHA256 parameter
profile required by `paysec-crypto`, so that capability cannot be exercised
end-to-end with the SoftHSM integration environment.

## Documentation

Detailed documentation is available in the individual crate READMEs:

* [`paysec`](crates/paysec/README.md)
* [`paysec-dukpt`](crates/paysec-dukpt/README.md)
* [`paysec-keyblock`](crates/paysec-keyblock/README.md)
* [`paysec-pinblock`](crates/paysec-pinblock/README.md)
* [`paysec-tr34`](crates/paysec-tr34/README.md)
* [`paysec-crypto`](crates/paysec-crypto/README.md)
* [`paysec-crypto-rustcrypto`](crates/paysec-crypto-rustcrypto/README.md)
* [`paysec-crypto-soft-aes`](crates/paysec-crypto-soft-aes/README.md)
* [`paysec-crypto-pkcs11`](crates/paysec-crypto-pkcs11/README.md)

Published API documentation is available through
[docs.rs](https://docs.rs/).

## Related Projects

### PIN Block Web Tool

The [PIN Block Web Tool](https://www.jointech.at/tools/pinblock/index.html)
provides a browser-based interface for generating and inspecting ISO 9564 PIN
block test data.

### Key Block Web Tool

The [Key Block Web Tool](https://www.jointech.at/tools/keyblock/index.html)
provides a browser-based interface for TR-31 key block testing and test-data
generation.

## Possible Future Work

Possible future areas include:

* opaque PKCS #11 key derivation for TR-31 Version D
* HSM-contained DUKPT derivation
* additional PKCS #11 provider capabilities and HSM interoperability testing
* additional TR-34 lifecycle protocols such as bind, unbind, and rebind
* additional TR-34 interoperability profiles
* ANSI X9.143 and ISO 20038 key-block extensions
* additional TR-31 key block versions
* additional PIN block formats
* additional payment cryptography and key-management functionality

These are possible areas of development rather than committed release plans.

### AI-assisted development

Parts of `paysec` predate the widespread availability of generative AI and
were developed without AI assistance.

More recent development has used AI tools selectively as part of an
author-directed workflow. This has included assistance with refactoring, code
review, documentation, and the development and review of unit and integration
tests.

AI-generated changes are not applied autonomously. Development is performed
incrementally, with proposed changes reviewed by the maintainer, added to the
codebase deliberately, tested, and inspected before being committed.

The project does not use autonomous AI agents to modify or maintain the
repository.

The overall architecture, public API design, cryptographic abstractions,
security boundaries, and project direction remain maintainer-designed and
maintainer-controlled. Responsibility for the resulting code and releases
remains with the project maintainer.


## License

`paysec` is licensed under the GNU General Public License Version 3.0 only
(`GPL-3.0-only`).

See [LICENSE](LICENSE) for the complete license terms.

Copyright © David Schmid.

The implementation may reference standards and protocols whose copyrights and
intellectual-property rights belong to their respective standards
organizations. Users are responsible for obtaining any standards documents or
licenses required for their use case.

Dependencies are distributed under their own licenses and should be reviewed
independently where required.

For questions about alternative licensing arrangements, contact David Schmid at
`david.schmid@mailbox.org`.
