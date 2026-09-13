# paysec

`paysec` is a Rust library for implementing, testing, and working with
payment-security standards used in retail payment systems.

The project currently focuses on PIN block processing and symmetric key blocks,
with an emphasis on AES-based standards and an architecture that separates
payment-standard logic from cryptographic implementations.

The library can be used with software cryptographic providers for development,
testing, interoperability work, and deterministic test-vector generation. Its
crypto abstraction is also designed to support providers that use opaque or
non-exportable key handles, such as future HSM-backed implementations.

## Current Status

`paysec` is under active development.

The current workspace version is **0.2.0** and requires **Rust 1.89 or newer**.

Currently implemented standards include:

* **ASC X9 TR 31-2018**

  * key block version `D`
  * AES-based key block protection
  * KBEK and KBAK derivation using AES-CMAC
  * key wrapping and unwrapping
  * key block headers and optional blocks
  * masked key lengths and payload padding
  * header and key block validation

* **ISO 9564 PIN block format 4**

  * PIN field encoding and decoding
  * PAN field encoding
  * AES-based PIN block enciphering and deciphering
  * PAN binding
  * provider-independent AES operations

* **ISO 9564 PIN block format 3**

  * PIN block encoding and decoding
  * PIN/PAN field processing
  * cryptographic protection is intentionally left to a separate operation

## Workspace Structure

`paysec` is organized as a Cargo workspace:

| Crate                      | Purpose                                                                                 |
| -------------------------- | --------------------------------------------------------------------------------------- |
| `paysec`                   | Convenience facade exposing the key block and PIN block crates                          |
| `paysec-crypto`            | Provider-independent cryptographic capability traits                                    |
| `paysec-crypto-soft-aes`   | `soft-aes` based software provider, primarily useful as a reference and testing backend |
| `paysec-crypto-rustcrypto` | Software provider based on RustCrypto AES, CBC, and CMAC implementations                |
| `paysec-pinblock`          | ISO 9564 PIN block processing                                                           |
| `paysec-keyblock`          | TR-31 key block processing                                                              |

The facade crate exposes the payment-standard functionality through:

```rust
paysec::pinblock
paysec::keyblock
```

The cryptographic provider crates remain separate dependencies so applications
can explicitly select the backend appropriate for their environment.

## Cryptographic Provider Model

Payment-standard processing is separated from cryptographic implementations.

The `paysec-crypto` crate defines capability traits such as:

```rust
AesBlockCipher<K>
AesCbc<K>
AesCmac<K>
AesCmacKeyDerivation<K>
```

The key type `K` is provider-specific.

A software provider can therefore operate on raw key material:

```text
KBPK -> &[u8]
KBEK -> Vec<u8>
KBAK -> Vec<u8>
```

while a future HSM provider may instead use opaque key objects:

```text
KBPK -> HsmKeyHandle
KBEK -> HsmKeyHandle
KBAK -> HsmKeyHandle
```

This allows the payment-standard implementation to remain independent of a
particular AES library, HSM vendor, or key-storage model.

Two software providers are currently included:

* `SoftAesProvider`
* `RustCryptoProvider`

Both are exercised against the same TR-31 and ISO 9564 format 4 test vectors to
verify provider-independent behavior.

No HSM provider is currently included in this repository.

## Installation

Version `0.2.0` is currently available from the GitHub repository and has not
yet been published to crates.io.

The `0.1.0` release currently available on crates.io represents the previous
single-crate architecture and does not provide the workspace and provider APIs
described in this README.

To use the current version directly from GitHub:

```toml
[dependencies]
paysec = { git = "https://github.com/5n00py/paysec" }
paysec-crypto-rustcrypto = { git = "https://github.com/5n00py/paysec" }
```

Alternatively, select the individual crates you need:

```toml
[dependencies]
paysec-pinblock = { git = "https://github.com/5n00py/paysec" }
paysec-keyblock = { git = "https://github.com/5n00py/paysec" }
paysec-crypto = { git = "https://github.com/5n00py/paysec" }
paysec-crypto-rustcrypto = { git = "https://github.com/5n00py/paysec" }
```

The `soft-aes` reference provider can be selected instead when appropriate:

```toml
[dependencies]
paysec = { git = "https://github.com/5n00py/paysec" }
paysec-crypto-soft-aes = { git = "https://github.com/5n00py/paysec" }
```

After the `0.2.0` workspace crates are published to crates.io, these Git
dependencies can be replaced with normal versioned Cargo dependencies.

## ISO 9564 Format 4 Example

The following example enciphers and then deciphers an ISO 9564 format 4 PIN
block using the RustCrypto provider:

```rust
use paysec::pinblock::{
    decipher_pinblock_iso_4,
    encipher_pinblock_iso_4,
};
use paysec_crypto_rustcrypto::RustCryptoProvider;

let provider = RustCryptoProvider::new();

let key = hex::decode(
    "00112233445566778899AABBCCDDEEFF",
)
.unwrap();

let pin = "1234";
let pan = "1234567890123456789";
let random_seed = vec![0xFF; 8];

let pin_block = encipher_pinblock_iso_4(
    &provider,
    key.as_slice(),
    pin,
    pan,
    random_seed,
)
.unwrap();

assert_eq!(
    hex::encode_upper(&pin_block),
    "28B41FDDD29B743E93124BD8E32D921E"
);

let recovered_pin = decipher_pinblock_iso_4(
    &provider,
    key.as_slice(),
    &pin_block,
    pan,
)
.unwrap();

assert_eq!(
    recovered_pin.expose_secret(),
    pin,
);
```

Decoded plaintext PINs are returned as `Pin` rather than ordinary `String`
values. See [Sensitive Data Handling](#sensitive-data-handling).

## TR-31 Example

The following example wraps and unwraps a key using TR-31 version `D`:

```rust
use paysec::keyblock::{
    tr31_unwrap,
    tr31_wrap,
    KeyBlockHeader,
};
use paysec_crypto::AesKeySize;
use paysec_crypto_rustcrypto::RustCryptoProvider;

let provider = RustCryptoProvider::new();

let header = KeyBlockHeader::new_with_values(
    "D",
    "P0",
    "A",
    "E",
    "00",
    "E",
)
.unwrap();

let key = hex::decode(
    "3F419E1CB7079442AA37474C2EFBF8B8",
)
.unwrap();

let random_seed = hex::decode(
    "1C2965473CE206BB855B01533782",
)
.unwrap();

let kbpk = hex::decode(
    "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6",
)
.unwrap();

let key_block = tr31_wrap(
    &provider,
    kbpk.as_slice(),
    AesKeySize::Bits256,
    header,
    &key,
    0,
    &random_seed,
)
.unwrap();

let (header, recovered_key) = tr31_unwrap(
    &provider,
    kbpk.as_slice(),
    AesKeySize::Bits256,
    &key_block,
)
.unwrap();

assert_eq!(header.version_id(), "D");

assert_eq!(
    recovered_key.expose_secret(),
    key.as_slice(),
);
```

The KBPK representation is provider-specific. A software provider uses raw key
bytes, while an HSM-backed provider could use an opaque key handle without
exposing the KBPK, KBEK, or KBAK to the payment-standard implementation.

## Sensitive Data Handling

`paysec` uses dedicated types for plaintext sensitive values created by the
library.

### `Pin`

Decoded or deciphered plaintext PINs are returned as `Pin`.

`Pin`:

* validates that the value contains 4 to 12 ASCII decimal digits,
* redacts its contents from `Debug`,
* zeroizes its owned memory when dropped,
* requires explicit access through `expose_secret()`.

For example:

```rust
let pin = recovered_pin.expose_secret();
```

### `SecretKey`

Plaintext key material returned by TR-31 unwrapping is returned as `SecretKey`.

`SecretKey`:

* redacts its contents from `Debug`,
* zeroizes its owned memory when dropped,
* requires explicit access through `expose_secret()`.

Temporary plaintext payload and PIN-field buffers used internally in sensitive
processing paths are also zeroized where practical.

These measures provide defense in depth against accidental disclosure and
residual process-memory contents. They do **not** guarantee that secrets have
never existed elsewhere in memory. Callers may retain their own copies, and
operating-system facilities such as swap, crash dumps, or process-memory
inspection are outside the scope of these protections.

## Security Considerations

The security properties of cryptographic operations depend on the selected
provider and deployment environment.

The software providers included in this repository operate on key material in
application memory. They are useful for:

* testing,
* interoperability work,
* deterministic standard test vectors,
* development,
* software-only applications where that security model is appropriate.

They do not provide the isolation or non-exportability guarantees of a Hardware
Security Module.

The provider abstraction is designed so that applications requiring stronger
key protection can use an implementation based on opaque key handles without
requiring the payment-standard logic to access raw provider-managed key
material.

### Randomness

Some operations, including TR-31 wrapping and ISO 9564 format 4 PIN field
construction, require random data.

`paysec` deliberately accepts this data from the caller rather than selecting a
random-number generator internally. This makes deterministic standard vectors
and reproducible testing possible and leaves entropy generation under
application or provider control.

The library does not assess the entropy quality of supplied random data.

Production applications are responsible for providing randomness appropriate
for their security requirements.

### Compliance

Using this library does not by itself establish compliance with PCI, ANSI, ISO,
or other payment-security requirements.

Production deployments may require additional controls including:

* certified HSMs,
* secure key ceremonies,
* access control,
* audit logging,
* secure entropy sources,
* key lifecycle management,
* process and host hardening,
* certification or validation against applicable standards.

Users are responsible for determining which requirements apply to their
environment.

## Error Handling

The payment-standard crates use typed errors.

Protocol, parsing, and validation failures are kept separate from errors
reported by cryptographic providers.

For provider-backed operations, APIs use generic error types such as:

```rust
PinBlockCryptoError<E>
Tr31CryptoError<E>
```

where `E` is the concrete error type of the selected cryptographic provider.

This allows provider-specific errors—including errors from a future HSM
integration—to remain available without converting them to strings or erasing
their concrete type.

## Development

The workspace currently targets:

```text
Rust edition: 2024
MSRV:         1.89
```

Run the complete test suite with:

```bash
cargo test --workspace
```

Run documentation tests with:

```bash
cargo test --workspace --doc
```

Check the complete workspace with:

```bash
cargo check --workspace
```

Both software cryptographic providers are tested against the same
payment-standard vectors.

## API Documentation

The source contains Rustdoc documentation for the public APIs and major
standards implementations, including executable examples.

After publication, crate documentation is available through
[docs.rs](https://docs.rs/).

Documentation can also be generated locally:

```bash
cargo doc --workspace --no-deps --open
```

## Related Projects

### PIN Block Web Tool

The [PIN Block Web Tool](https://www.jointech.at/tools/pinblock/index.html)
provides a browser-based interface for generating and inspecting ISO 9564 PIN
block test data.

It demonstrates use of `paysec` through WebAssembly.

### Key Block Web Tool

The [Key Block Web Tool](https://www.jointech.at/tools/keyblock/index.html)
provides a browser-based interface for TR-31 key block testing and test-data
generation.

## Possible Future Work

Possible future development areas include:

* HSM-backed cryptographic providers,
* TR-34 asymmetric key distribution,
* ANSI X9.143 and ISO 20038 related key-block extensions,
* additional TR-31 key block versions,
* additional PIN block formats,
* additional payment cryptography and key-management functionality.

These items describe possible areas of development rather than committed release plans.

## License

`paysec` is licensed under the GNU General Public License Version 3.0
(`GPL-3.0`).

See [LICENSE](LICENSE) for the complete license terms.

Copyright © David Schmid.

The implementation may reference standards and protocols whose copyrights and
intellectual-property rights belong to their respective standards
organizations. Users are responsible for obtaining any standards documents or
licenses required for their use case.

Dependencies used by the project are distributed under their own licenses and
should be reviewed independently where required.

For questions about alternative licensing arrangements, contact David Schmid at
`david.schmid@mailbox.org`.
