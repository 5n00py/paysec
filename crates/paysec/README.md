# paysec

`paysec` is the facade crate for the
[paysec](https://github.com/5n00py/paysec) payment-security workspace.

It provides a convenient entry point for functionality related to payment
security standards while keeping PIN block processing, key block processing,
and cryptographic implementations separated into focused crates.

## Current functionality

The facade currently exposes:

* `paysec::pinblock` — PIN block functionality, including ISO 9564 format 3
  and format 4 processing.
* `paysec::keyblock` — key block functionality, including TR-31:2018 version D
  wrapping and unwrapping.

Cryptographic operations are provided separately through the `paysec-crypto`
provider interfaces.

## Installation

Add the facade crate:

```toml
[dependencies]
paysec = "0.2"
```

For cryptographic operations, also select a provider. For example, using the
RustCrypto-based provider:

```toml
[dependencies]
paysec = "0.2"
paysec-crypto-rustcrypto = "0.2"
```

Alternatively, the `soft-aes` provider is available:

```toml
[dependencies]
paysec = "0.2"
paysec-crypto-soft-aes = "0.2"
```

## Workspace crates

The paysec project is split into several crates:

* `paysec` — facade crate
* `paysec-pinblock` — PIN block processing
* `paysec-keyblock` — TR-31 key block processing
* `paysec-crypto` — cryptographic provider interfaces
* `paysec-crypto-rustcrypto` — RustCrypto provider
* `paysec-crypto-soft-aes` — soft-aes provider

This separation allows applications to depend only on the functionality and
cryptographic backend they require.

## Cryptographic providers

The cryptographic API is provider-based rather than tied to one AES
implementation.

The included providers use software-managed raw key material. The provider
interfaces are designed so that other implementations can use different key
representations, including opaque handles managed by an HSM.

No HSM provider is currently included.

## Sensitive data

Plaintext sensitive values returned by the library use dedicated types where
appropriate:

* `Pin` for plaintext PIN values
* `SecretKey` for plaintext key material returned from TR-31 unwrapping

These types redact their contents from `Debug`, zeroize owned secret data on
drop, and require explicit access through `expose_secret()`.

Applications remain responsible for the complete lifecycle and protection of
sensitive data outside these types.

## Documentation

API documentation is available on
[docs.rs](https://docs.rs/paysec).

For architecture, security considerations, examples, development information,
and the complete workspace overview, see the
[paysec repository](https://github.com/5n00py/paysec).

## License

Licensed under the GNU General Public License version 3 (`GPL-3.0`).

Copyright © David Schmid.

Payment-security standards referenced by this project remain the intellectual
property of their respective standards organizations and rights holders.
