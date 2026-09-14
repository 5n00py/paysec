# paysec

`paysec` is a Rust project for implementing, testing, and working with
payment-security standards used in retail payment systems.

The project provides standards-oriented building blocks for payment
cryptography, including PIN blocks, symmetric key blocks, and AES DUKPT key
derivation.

Payment-standard logic is separated from cryptographic implementations through
provider traits, allowing applications to select the cryptographic backend
appropriate for their environment.

## Current Status

`paysec` is under active development and currently requires **Rust 1.89 or
newer**.

Implemented functionality includes:

- **ANSI X9.24-3 AES DUKPT**
  - receiving-side / host key derivation
  - native 96-bit AES Key Serial Numbers
  - AES-128, AES-192, and AES-256
  - Initial Key derivation
  - transaction working-key derivation
  - DUKPT Update Key derivation

- **ASC X9 TR-31-2018**
  - key block Version `D`
  - AES-based key block protection
  - key wrapping and unwrapping
  - key block headers and optional blocks
  - KBEK and KBAK derivation using AES-CMAC

- **ISO 9564 PIN blocks**
  - Format 3 encoding and decoding
  - Format 4 encoding and decoding
  - AES-based Format 4 enciphering and deciphering
  - PIN and PAN processing

## Workspace

The project is organized as independently versioned Cargo crates.

| Crate | Version | Purpose |
| --- | --- | --- |
| [`paysec`](crates/paysec/README.md) | `0.3.0` | Convenience facade for payment-security functionality |
| [`paysec-dukpt`](crates/paysec-dukpt/README.md) | `0.1.0` | ANSI X9.24-3 AES DUKPT host-side key derivation |
| [`paysec-keyblock`](crates/paysec-keyblock/README.md) | `0.2.1` | TR-31 key block processing |
| [`paysec-pinblock`](crates/paysec-pinblock/README.md) | `0.2.1` | ISO 9564 PIN block processing |
| [`paysec-crypto`](crates/paysec-crypto/README.md) | `0.2.1` | Provider-independent cryptographic capability traits |
| [`paysec-crypto-rustcrypto`](crates/paysec-crypto-rustcrypto/README.md) | `0.2.1` | RustCrypto-based software provider |
| [`paysec-crypto-soft-aes`](crates/paysec-crypto-soft-aes/README.md) | `0.2.1` | `soft-aes` based software provider |

Each crate README contains its supported functionality, installation
instructions, examples, and crate-specific security considerations.

## Facade

The `paysec` crate exposes the high-level payment-security crates through:

```rust
paysec::dukpt
paysec::keyblock
paysec::pinblock
````

Cryptographic providers remain separate dependencies so applications can
explicitly select the backend appropriate for their environment.

## Architecture

Payment-standard processing is kept separate from cryptographic
implementations.

The `paysec-crypto` crate defines provider traits such as:

```rust
AesBlockCipher<K>
AesCbc<K>
AesCmac<K>
AesCmacKeyDerivation<K>
```

The key type is provider-specific. Software providers can operate on raw key
material, while the abstraction leaves room for providers using opaque or
non-exportable key handles.

Two software providers are currently included:

* `RustCryptoProvider`
* `SoftAesProvider`

No HSM-backed provider is currently included.

## Installation

For the facade crate:

```toml
[dependencies]
paysec = "0.3"
```

Cryptographic operations also require a provider. For example:

```toml
[dependencies]
paysec = "0.3"
paysec-crypto = "0.2.1"
paysec-crypto-rustcrypto = "0.2.1"
```

Applications can also depend directly on individual crates:

```toml
[dependencies]
paysec-dukpt = "0.1"
paysec-keyblock = "0.2.1"
paysec-pinblock = "0.2.1"
paysec-crypto = "0.2.1"
paysec-crypto-rustcrypto = "0.2.1"
```

See the individual crate READMEs for detailed usage examples.

## Security

The software providers included in this repository operate on key material in
application memory. They are suitable for development, interoperability work,
standard test vectors, and environments where software-managed keys are
appropriate.

They do not provide the isolation or non-exportability guarantees of a
Hardware Security Module.

The payment-standard crates use dedicated secret types where appropriate.
These types redact secret values from debug output and zeroize owned secret
memory when dropped.

These protections are defense in depth and do not guarantee that secret values
have never existed elsewhere in process memory.

Some operations require caller-provided random data. The library deliberately
does not select a random-number generator internally, allowing deterministic
standard vectors and leaving entropy generation under application or provider
control.

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
cargo check --workspace
```

Run the test suite:

```bash
cargo test --workspace
```

Run documentation tests:

```bash
cargo test --workspace --doc
```

Generate API documentation locally:

```bash
cargo doc --workspace --no-deps --open
```

## Documentation

Detailed documentation is available in the individual crate READMEs:

* [`paysec`](crates/paysec/README.md)
* [`paysec-dukpt`](crates/paysec-dukpt/README.md)
* [`paysec-keyblock`](crates/paysec-keyblock/README.md)
* [`paysec-pinblock`](crates/paysec-pinblock/README.md)
* [`paysec-crypto`](crates/paysec-crypto/README.md)
* [`paysec-crypto-rustcrypto`](crates/paysec-crypto-rustcrypto/README.md)
* [`paysec-crypto-soft-aes`](crates/paysec-crypto-soft-aes/README.md)

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

* HSM-backed cryptographic providers
* TR-34 asymmetric key distribution
* ANSI X9.143 and ISO 20038 key-block extensions
* additional TR-31 key block versions
* additional PIN block formats
* additional payment cryptography and key-management functionality

These are possible areas of development rather than committed release plans.

## License

`paysec` is licensed under the GNU General Public License Version 3.0
(`GPL-3.0`).

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
