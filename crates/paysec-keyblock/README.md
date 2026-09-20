# paysec-keyblock

TR-31 key-block support for payment-security applications.

The crate provides functionality for wrapping and unwrapping cryptographic
keys using the TR-31 key-block format.

## Supported functionality

The current implementation focuses on TR-31 Version D and includes:

- TR-31 key-block header handling
- optional blocks
- AES-CMAC-based KBEK and KBAK derivation
- authenticated key wrapping
- key-block unwrapping and authentication
- masked key lengths and payload padding
- structural and header validation
- zeroizing secret key material

Cryptographic operations are delegated to a `paysec-crypto` provider.

## Installation

```toml
[dependencies]
hex = "0.4"
paysec-keyblock = "0.3"
paysec-crypto = "0.3"
paysec-crypto-rustcrypto = "0.3"
````

## Example

The following example wraps and unwraps a key using TR-31 Version D with the
RustCrypto provider:

```rust
use paysec_crypto::AesKeySize;
use paysec_crypto_rustcrypto::RustCryptoProvider;

use paysec_keyblock::{
    tr31_unwrap,
    tr31_wrap,
    KeyBlockHeader,
};

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

assert_eq!(
    header.version_id(),
    "D",
);

assert_eq!(
    recovered_key.expose_secret(),
    key.as_slice(),
);
```

## Secret key material

Plaintext key material returned by TR-31 unwrapping is represented by
`SecretKey`.

`SecretKey`:

* redacts its contents from `Debug`
* zeroizes owned key material when dropped
* requires explicit access through `expose_secret()`

The software cryptographic providers operate on raw key material in process
memory. Applications requiring stronger isolation remain responsible for
selecting an appropriate provider and key-management environment.

## Randomness

TR-31 wrapping requires caller-supplied random data.

The crate deliberately does not choose a random-number generator internally.
This enables deterministic standards testing and leaves entropy generation
under application or provider control.

Production applications are responsible for providing randomness appropriate
for their security requirements.

## Security

Using this crate does not by itself establish compliance with PCI, ANSI, or
other payment-security requirements.

Applications remain responsible for secure key storage, access control, key
lifecycle management, and deployment controls appropriate to their
environment.

For the complete project overview, see the
[`paysec` repository](https://github.com/5n00py/paysec).
