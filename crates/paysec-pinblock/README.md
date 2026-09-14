# paysec-pinblock

ISO 9564 PIN-block functionality for payment-security applications.

The crate provides PIN modeling and PIN-block processing while keeping
cryptographic operations separate from PIN-block format logic.

## Supported functionality

The current implementation includes:

- ISO 9564 Format 3 PIN blocks
- ISO 9564 Format 4 PIN blocks
- PIN validation
- PAN processing and binding
- AES-based Format 4 enciphering and deciphering
- provider-independent cryptographic operations
- zeroizing plaintext PIN storage

## Installation

```toml
[dependencies]
hex = "0.4"
paysec-pinblock = "0.2.1"
paysec-crypto-rustcrypto = "0.2.1"
````

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

## Security

PINs and plaintext PIN-block data are sensitive payment-authentication data.
Applications must apply the operational and security controls required by
their environment.

Using this crate does not by itself establish PCI or ISO compliance.

For the complete project overview, see the
[`paysec` repository](https://github.com/5n00py/paysec).
