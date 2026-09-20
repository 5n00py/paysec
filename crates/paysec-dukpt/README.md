# paysec-dukpt

AES DUKPT key derivation according to ANSI X9.24-3 for payment-security
applications.

The current implementation focuses on receiving-side / host derivation using
the native 96-bit AES DUKPT Key Serial Number (KSN).

## Supported functionality

The crate currently supports:

- AES-128, AES-192, and AES-256 Base Derivation Keys
- Initial Key derivation
- native 96-bit AES DUKPT KSNs
- receiving-side transaction-counter derivation
- AES working-key derivation
- working-key purpose separation
- working keys of equal or lower strength than the derivation key
- DUKPT Update Key derivation
- provider-independent AES operations

The implementation has been tested using ANSI X9.24-3 Annex B vectors,
supplemental ASC X9 vectors, and additional AES-192 vectors generated from the
ASC X9 reference implementation.

## Installation

```toml
[dependencies]
paysec-dukpt = "0.2"
paysec-crypto = "0.3"
paysec-crypto-rustcrypto = "0.3"
````

## Example

```rust
use paysec_crypto::AesKeySize;
use paysec_crypto_rustcrypto::RustCryptoProvider;

use paysec_dukpt::{
    derive_working_key,
    KeySerialNumber,
    WorkingKeyUsage,
};

let provider = RustCryptoProvider::new();

let bdk =
    hex::decode(
        "FEDCBA9876543210F1F1F1F1F1F1F1F1",
    )
    .unwrap();

let ksn =
    KeySerialNumber::from_parts(
        0x12345678,
        0x90123456,
        0x0000_0001,
    );

let pin_key =
    derive_working_key(
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
        pin_key.expose_secret(),
    ),
    "AF8CB133A78F8DC2D1359F18527593FB",
);
```

## DUKPT model

For host-side derivation, the basic relationship is:

```text
BDK + KSN
   |
   v
Initial Key
   |
   | transaction-counter derivation path
   v
Intermediate Derivation Key
   |
   | usage + requested AES key size
   v
Working Key
```

The KSN is non-secret. The BDK and all derived keys are secret.

## Scope

The current crate intentionally does not implement:

* transaction-originating device state management
* 80-bit KSN compatibility mode
* TDEA DUKPT

The focus is native AES DUKPT receiving-side derivation.

## Cryptographic providers

Cryptographic AES operations are delegated through `paysec-crypto`.

The current software providers expose key material in process memory. A future
HSM-backed integration may require additional provider capabilities to keep
derived keys non-exportable.

## Security

`DukptKey` owns software-visible derived key material, redacts debug output,
and zeroizes its owned memory when dropped.

DUKPT key derivation alone does not provide replay detection or transaction
state management. Receiving systems remain responsible for those controls.

For project-level documentation, see the
[`paysec` repository](https://github.com/5n00py/paysec).

