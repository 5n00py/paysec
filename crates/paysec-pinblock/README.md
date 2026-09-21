# paysec-pinblock

ISO 9564 PIN-block functionality for payment-security applications.

The crate provides PIN modeling and PIN-block processing while keeping
cryptographic operations separate from PIN-block format logic.

## Supported functionality

The current implementation includes:

* ISO 9564 Format 3 PIN blocks
* ISO 9564 Format 4 PIN blocks
* PIN validation
* PAN processing and binding
* AES-based Format 4 enciphering and deciphering
* provider-independent cryptographic operations
* support for software and PKCS #11-backed AES providers
* zeroizing plaintext PIN storage

## Installation

Using the RustCrypto software provider:

```toml
[dependencies]
hex = "0.4"
paysec-pinblock = "0.3.1"
paysec-crypto-rustcrypto = "0.3"
```

Using the PKCS #11 provider with an HSM or compatible token:

```toml
[dependencies]
paysec-pinblock = "0.3.1"
paysec-crypto-pkcs11 = "0.1"
```

Applications that need common cryptographic types or traits can also depend
directly on `paysec-crypto`.

## ISO 9564 Format 4 example

The following example enciphers and then deciphers an ISO 9564 Format 4 PIN
block using the RustCrypto provider:

```rust
use paysec_crypto_rustcrypto::RustCryptoProvider;

use paysec_pinblock::{
    decipher_pinblock_iso_4,
    encipher_pinblock_iso_4,
};

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
    "28B41FDDD29B743E93124BD8E32D921E",
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

## Cryptographic providers

ISO 9564 Format 4 cryptographic processing is expressed through the
`AesBlockCipher<K>` capability defined by `paysec-crypto`.

The key representation is therefore provider-specific.

### Software providers

Software providers such as `paysec-crypto-rustcrypto` and
`paysec-crypto-soft-aes` operate on raw AES key material supplied by the
application.

### PKCS #11 provider

`paysec-crypto-pkcs11` implements the required AES block capability for opaque
`Pkcs11Key` references.

This allows the AES key used for Format 4 enciphering and deciphering to remain
as an existing PKCS #11 secret-key object rather than being supplied to the
application as raw key bytes.

For example, the provider and key can be configured independently of the
PIN-block operation:

```rust
use paysec_crypto_pkcs11::{
    Pkcs11Auth,
    Pkcs11Config,
    Pkcs11Key,
    Pkcs11Provider,
    TokenSelector,
};

let config = Pkcs11Config::new(
    "/path/to/pkcs11-module.so",
    TokenSelector::label("payment-token"),
);

let auth = Pkcs11Auth::user_pin("123456");

let provider = Pkcs11Provider::connect(&config, &auth)?;
let key = Pkcs11Key::by_id([0x10]);
```

The resulting `provider` and `key` can be passed to the same Format 4 API used
with software providers.

The PKCS #11 provider uses the token's AES primitive internally and does not
read the persistent AES key value into the application.

Actual support depends on the selected PKCS #11 token and its configured key
attributes.

## PIN handling

Decoded or deciphered plaintext PINs are represented by `Pin`.

`Pin`:

* accepts 4 to 12 ASCII decimal digits
* redacts its contents from `Debug`
* zeroizes its owned memory when dropped
* requires explicit access through `expose_secret()`

Temporary plaintext buffers used internally in sensitive processing paths are
also zeroized where practical.

These protections reduce accidental disclosure and residual process-memory
contents, but they do not guarantee that secret values have never existed
elsewhere in memory.

## Randomness

ISO 9564 Format 4 PIN-field construction requires caller-supplied random data.

The crate deliberately does not select a random-number generator internally.
This supports deterministic standards testing and leaves entropy generation
under application or provider control.

Production applications are responsible for supplying randomness appropriate
for their security requirements.

A PKCS #11-backed application can, for example, obtain random bytes from a
provider implementing `RandomBytes`, but randomness remains an explicit input
to the PIN-block API rather than being generated internally by this crate.

## Security

PINs and plaintext PIN-block data are sensitive payment-authentication data.
Applications must apply the operational and security controls required by
their environment.

When a software cryptographic provider is used, AES key material is generally
present in application memory.

When `paysec-crypto-pkcs11` is used, the persistent AES key can remain inside
the selected PKCS #11 token and be referenced through an opaque `Pkcs11Key`.

This does **not** make the entire PIN-block operation HSM-contained. PIN values,
PAN data, Format 4 intermediate data, caller-supplied randomness, and the
resulting encrypted PIN block are processed by the application as required by
the current API.

Whether a PKCS #11 key is actually non-exportable depends on the token, key
attributes, and provisioning process. Use of `Pkcs11Provider` alone does not
establish that a key was securely generated or configured as
non-extractable.

Using this crate does not by itself establish PCI or ISO compliance.

For the complete project overview, see the
[`paysec` repository](https://github.com/5n00py/paysec).
