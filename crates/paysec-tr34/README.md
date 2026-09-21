# paysec-tr34

`paysec-tr34` implements ASC X9 TR-34 key transport for payment-security
applications.

The crate currently focuses on **KDH-side, two-pass key export using AES**, and
emits the complete DER-encoded CMS `ContentInfo` containing the TR-34 KDH Key
Token (`KTKDH`).

Two encoding profiles are supported:

* **`Tr34Profile::Strict`** — standards-oriented CMS / ASN.1 encoding.
* **`Tr34Profile::AnnexB2019`** — interoperability encoding based on the
  conventions demonstrated by the ASC X9 TR 34-2019 Annex B examples.

The cryptographic backend is provider-neutral: `paysec-tr34` depends on
capabilities defined by `paysec-crypto` rather than selecting a concrete
cryptographic implementation itself.

The repository includes both software and PKCS #11-backed providers capable of
satisfying the cryptographic interfaces required by the TR-34 export API.

> **Current scope:** two-pass KDH export, AES-128-CBC content encryption,
> RSAES-OAEP-SHA256 key wrapping, and RSA PKCS#1 v1.5 SHA-256 signatures. TDEA
> / TDES transport is not implemented.

## What is TR-34?

TR-34 is a payment-industry key-distribution protocol for transporting
symmetric keys using asymmetric cryptography.

A typical use case is a **Key Distribution Host (KDH)** securely delivering a
symmetric key to a **Key Receiving Device (KRD)** such as a payment terminal,
PIN-entry device, or another secure cryptographic device across a channel that
does not itself need to be trusted for confidentiality.

At a high level:

1. The KRD has an asymmetric key pair and an X.509 credential.
2. The KDH has a signing key pair and an X.509 credential.
3. The KDH creates a symmetric key block for the key being transported.
4. The key block is encrypted under a fresh ephemeral symmetric key.
5. The ephemeral key is wrapped using the KRD public key.
6. The transport data is signed using the KDH private key.
7. A KDH certificate revocation list is included in the complete key token.
8. The KRD can verify the KDH signature, recover the ephemeral key with its
   private key, and then recover the transported symmetric key.

In the **two-pass** protocol, the KRD first supplies a fresh random nonce. The
KDH includes that nonce in the signed data, allowing the KRD to reject replayed
key-transport messages.

TR-34 is commonly relevant to remote key loading and other controlled
payment-key distribution workflows where a host needs to establish keys in
remote cryptographic devices without relying on a pre-shared transport key.

## Supported functionality

| Capability                                        | Status                                                 |
| ------------------------------------------------- | ------------------------------------------------------ |
| KDH-side key export                               | Supported                                              |
| Two-pass protocol                                 | Supported                                              |
| One-pass protocol                                 | Not implemented                                        |
| AES-based key transport                           | Supported                                              |
| TDEA / TDES key transport                         | Not implemented                                        |
| Strict CMS / normative-style encoding             | Supported                                              |
| TR-34 2019 Annex B compatibility encoding         | Supported                                              |
| KRD-side token verification / decryption / import | Not implemented                                        |
| Certificate-path validation                       | Not performed                                          |
| Certificate validity / key-usage validation       | Not performed                                          |
| CRL freshness / signature / revocation validation | Not performed                                          |
| RTKRD generation                                  | Not performed; the KRD nonce is supplied by the caller |
| Bind / unbind / rebind protocols                  | Not implemented                                        |
| Software cryptographic provider                   | Included                                               |
| PKCS #11 / HSM-backed provider                    | Included                                               |

The implementation is intentionally narrow: it provides a well-defined
key-token construction primitive rather than trying to own the complete PKI,
device-lifecycle, or key-management system around TR-34.

## Installation

Add the TR-34 crate and a cryptographic provider appropriate for your
environment.

For example, using the RustCrypto software provider:

```toml
[dependencies]
paysec-tr34 = "0.1"
paysec-crypto-rustcrypto = "0.3"
```

Or using the PKCS #11 provider with an HSM or compatible token:

```toml
[dependencies]
paysec-tr34 = "0.1"
paysec-crypto-pkcs11 = "0.1"
```

Provider-specific key loading or selection may require additional
configuration or dependencies.

The payment-standard layer and cryptographic implementation are intentionally
separate so an application can use software-managed keys during development or
opaque PKCS #11 key references in an HSM-backed deployment without changing
the TR-34 protocol API.

## Public API

The main types are:

```rust
use paysec_tr34::{
    KdhCredential,
    KdhCrl,
    KrdCredential,
    Tr34Profile,
    TwoPassKeyExportRequest,
    export_key_two_pass,
};
```

`KdhCredential`, `KrdCredential`, and `KdhCrl` accept DER-encoded X.509
material.

`TwoPassKeyExportRequest` contains the TR-34 protocol inputs, while the KRD
encryption key and KDH signing key are passed separately because their concrete
representation belongs to the cryptographic provider.

`export_key_two_pass` returns the complete wire-level DER encoding of the TR-34
CMS `ContentInfo`.

## Strict CMS example

`Tr34Profile::Strict` is the default profile.

The following example assumes that `provider`, `krd_public_key`, and
`kdh_signing_key` have already been created using a cryptographic provider
implementing the required `paysec-crypto` traits.

```rust
use paysec_tr34::{
    KdhCredential,
    KdhCrl,
    KrdCredential,
    TwoPassKeyExportRequest,
    export_key_two_pass,
};

// DER-encoded credentials and CRL supplied by the application.
let kdh_credential = KdhCredential::from_der(kdh_certificate_der)?;
let krd_credential = KrdCredential::from_der(krd_certificate_der)?;
let kdh_crl = KdhCrl::from_der(kdh_crl_der)?;

// Symmetric key being transported.
let clear_key = [
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10,
];

// TR-31-style Key Block Header carried by the TR-34 message.
let key_block_header = b"A0256K0TB00E0000";

// Fresh nonce previously generated by the KRD for this two-pass exchange.
let krd_random_nonce = [
    0x16, 0x7E, 0xB0, 0xE7,
    0x27, 0x81, 0xE4, 0x94,
    0x01, 0x12, 0x23, 0x34,
    0x45, 0x56, 0x67, 0x78,
];

let request = TwoPassKeyExportRequest::new(
    &kdh_credential,
    &krd_credential,
    &clear_key,
    key_block_header,
    &krd_random_nonce,
    &kdh_crl,
);

// Strict is the default profile.
let token_der = export_key_two_pass(
    &mut provider,
    request,
    &krd_public_key,
    &kdh_signing_key,
)?;

// `token_der` is the complete DER-encoded CMS ContentInfo / KTKDH.
```

The strict profile is intended for standards-oriented implementations that
expect normal CMS structure and canonical DER behavior.

## Annex B 2019 compatibility example

Some deployed TR-34 integrations follow the encoding conventions demonstrated
by the informative examples in ASC X9 TR 34-2019 Annex B rather than the
normative CMS / ASN.1 interpretation.

For those environments, select `Tr34Profile::AnnexB2019`:

```rust
use paysec_tr34::{
    Tr34Profile,
    TwoPassKeyExportRequest,
    export_key_two_pass,
};

let request = TwoPassKeyExportRequest::new(
    &kdh_credential,
    &krd_credential,
    &clear_key,
    key_block_header,
    &krd_random_nonce,
    &kdh_crl,
)
.with_profile(Tr34Profile::AnnexB2019);

let token_der = export_key_two_pass(
    &mut provider,
    request,
    &krd_public_key,
    &kdh_signing_key,
)?;
```

The cryptographic operation is still a two-pass AES-based TR-34 export. The
profile changes the **wire encoding conventions** required for Annex B
interoperability.

## Encoding profiles

The public API exposes coherent profiles rather than individual compatibility
switches.

| Encoding detail                 | `Strict`                                 | `AnnexB2019`                             |
| ------------------------------- | ---------------------------------------- | ---------------------------------------- |
| KeyBlock version                | `INTEGER 0`                              | `INTEGER 1`                              |
| KeyBlock header                 | bare `OCTET STRING`                      | `id-data` Attribute wrapper              |
| `encryptedContent` placement    | CMS `EncryptedContentInfo` sibling field | inside the content-encryption `SEQUENCE` |
| AES-CBC IV                      | 16 bytes                                 | 16 bytes                                 |
| RSAES-OAEP parameters           | PKCS#1 tagged form                       | Annex B sample representation            |
| `SignedAttributes` ordering     | canonical DER `SET OF` ordering          | Annex B sample order                     |
| outer `SignedData.version`      | CMS-derived version `3`                  | `INTEGER 1`                              |
| `SignerInfo.signatureAlgorithm` | `sha256WithRSAEncryption`                | `rsaEncryption`                          |
| KDH CRL                         | included                                 | included                                 |

`Strict` is the default.

The important design principle is that an application chooses a named
interoperability profile rather than manually combining ASN.1 quirks that may
not make sense together.

For a deeper discussion, see [`docs/compatibility.md`](docs/compatibility.md).

## Why does an Annex B compatibility profile exist?

TR-34 2019 contains a useful but important distinction:

* **Annex D is normative ASN.1.**
* **Annex B is informative example material.**

Several Annex B encodings differ from the normative definitions or from normal
CMS encoding rules. Some of those differences also appear in real
interoperability ecosystems, which means simply producing canonical CMS is not
always sufficient when communicating with an existing TR-34 implementation.

`AnnexB2019` exists to model that interoperability family explicitly instead of
contaminating the strict path with special cases.

It is **not** intended to reproduce every defect in the published vectors.

### KeyBlock representation

The normative ASN.1 defines the KeyBlock version as `v1(0)` and the Key Block
Header as an `OCTET STRING`.

The published AES KeyBlock in Annex B instead uses:

* version `INTEGER 1`;
* an `id-data` Attribute wrapper around the Key Block Header.

`AnnexB2019` reproduces those sample encoding conventions.

### `encryptedContent` placement

Normal CMS `EncryptedContentInfo` encodes `contentEncryptionAlgorithm` and
`encryptedContent` as sibling fields.

The Annex B examples place `encryptedContent` inside the `SEQUENCE` used for
the content-encryption algorithm.

That is not normal CMS structure, but it is part of the compatibility profile
because implementations exist that expect this layout.

### RSAES-OAEP parameters

The strict profile uses the normal PKCS#1 tagged RSAES-OAEP parameter encoding.

The Annex B compatibility profile preserves the parameter representation
demonstrated by the published sample.

### `SignedAttributes` ordering

In DER, a `SET OF` is canonically ordered.

The Annex B examples present the signed attributes in a fixed example order
instead. Because the signature is calculated over the encoded
`SignedAttributes`, reordering them changes the bytes being signed.

`AnnexB2019` therefore preserves the Annex B attribute order all the way
through signature generation and emitted `SignerInfo`.

### `SignedData.version`

The B.9 prose describes the two-pass outer `SignedData` as version `3`, which
is consistent with CMS when the encapsulated content type is
`id-envelopedData`.

The actual B.9.1 sample token encodes version `1`.

The profiles intentionally make that difference explicit:

* `Strict` -> version `3`
* `AnnexB2019` -> version `1`

### Signature `AlgorithmIdentifier`

The B.9 prose identifies `sha256WithRSAEncryption`, while the published sample
representation uses `rsaEncryption` in `SignerInfo`.

The actual cryptographic operation in this crate remains an RSA PKCS#1 v1.5
SHA-256 signature. The profile controls how the signature algorithm is
identified on the wire:

* `Strict` -> `sha256WithRSAEncryption`
* `AnnexB2019` -> `rsaEncryption`

## Published AES-vector inconsistencies

The TR-34 2019 AES material contains inconsistencies that should be understood
before treating the Annex B examples as byte-for-byte normative vectors.

### The published AES-CBC IV is only eight bytes

Annex B serializes this IV parameter:

```text
0123456789ABCDEF
```

AES-CBC requires a 16-byte IV.

The published AES key, first plaintext block, and first ciphertext block allow
the IV actually used for encryption to be recovered mathematically. The
recovered value is:

```text
0123456789ABCDEF0000000000000000
```

The test suite derives this value from the vector rather than assuming the
trailing zero bytes.

`AnnexB2019` **does not emit an invalid eight-byte AES IV**. It always uses a
proper 16-byte IV.

### The published AES ciphertext contains a different Key Block Header

The separately published AES KeyBlock contains:

```text
D0256K0AB00E0000
```

However, decrypting the published AES `EnvelopedData` ciphertext with the
recovered IV produces a valid padded KeyBlock containing:

```text
A0256K0TB00E0000
```

The encrypted sample therefore was not generated from the independently
published AES KeyBlock fixture.

The conformance tests preserve both pieces of evidence rather than silently
normalizing one into the other.

### Compatibility means coherent interoperability, not defect reproduction

The goal of `AnnexB2019` is to reproduce the **encoding family** demonstrated
by Annex B where that behavior is useful for interoperability.

It deliberately does not reproduce cryptographically invalid behavior such as
an eight-byte AES-CBC IV.

## Cryptographic construction

The current AES two-pass export performs the following operations:

```text
KRD random nonce
      |
      v
+-----------------------------+
| SignedAttributes            |
| - contentType               |
| - randomNonce               |
| - Key Block Header          |
| - messageDigest             |
+-----------------------------+
             |
             | signed by KDH
             v
        SignerInfo
             |
             v
        +-----------+
        | SignedData|---- includes KDH CRL
        +-----------+
             ^
             |
        EnvelopedData
             ^
             |
   +-----------------------+
   | encrypted KeyBlock    |
   | AES-128-CBC under KE  |
   +-----------------------+
             ^
             |
         ephemeral KE
             |
             | RSAES-OAEP-SHA256
             v
      encrypted for KRD
```

The exact ASN.1 representation depends on the selected `Tr34Profile`.

## Cryptographic providers

`paysec-tr34` does not own the concrete cryptographic keys.

`export_key_two_pass` requires a provider implementing the capabilities needed
by the protocol:

```text
RandomBytes
AesCbc<[u8]>
RsaOaepSha256Encrypt<KrdKey>
RsaPkcs1v15Sha256Sign<KdhKey>
```

The key types are generic.

A software provider can use ordinary RSA key objects and raw AES material,
while a PKCS #11 provider can resolve opaque RSA key references to key objects
stored in an HSM or compatible token without changing the TR-34 protocol API.

The repository currently includes two providers capable of satisfying these
TR-34 trait requirements.

### RustCrypto provider

`paysec-crypto-rustcrypto` is a software implementation suitable for
development, testing, interoperability work, and environments where
software-managed keys are appropriate.

It performs the required AES, RSA, and random-generation operations in
software.

### PKCS #11 provider

`paysec-crypto-pkcs11` provides the required capabilities through PKCS #11.

The KRD RSA public key and KDH RSA signing key can be represented by opaque
`Pkcs11Key` references to objects already provisioned in an HSM or compatible
token.

The ephemeral AES key used by the TR-34 construction is intentionally
generated as host-resident material by the current TR-34 API. For the
AES-CBC operation, `Pkcs11Provider` imports this key as a temporary
non-persistent PKCS #11 session object, performs the operation, and destroys
the object immediately afterward.

The provider's token RNG is used for `RandomBytes`.

A compile-time integration test in `paysec-crypto-pkcs11` verifies that
`Pkcs11Provider` satisfies the actual trait requirements of
`export_key_two_pass`.

Actual mechanism and parameter support still depends on the selected PKCS #11
token.

In particular, the SoftHSM implementation used by the project's PKCS #11
integration environment does not support the SHA-256/MGF1-SHA256 parameter
profile required for `CKM_RSA_PKCS_OAEP`. SoftHSM therefore cannot currently
run the complete TR-34 PKCS #11 flow end-to-end.

The provider implementation is not weakened to SHA-1 to accommodate SoftHSM.
A PKCS #11 HSM supporting the required RSA-OAEP profile can use the existing
provider implementation.

## Security and validation responsibilities

`export_key_two_pass` constructs the TR-34 key token. It does **not** establish
the complete trust policy around the operation.

The application is responsible for validating whatever its deployment
requires, including:

* the KDH and KRD certificate chains;
* certificate validity periods;
* certificate key usage and other certificate-policy requirements;
* CRL signature and freshness;
* KDH revocation status;
* the expected identity of the KRD;
* that `krd_public_key` actually corresponds to the supplied KRD credential;
* that `kdh_signing_key` actually corresponds to the supplied KDH credential;
* generation, storage, and freshness tracking of the KRD two-pass nonce;
* semantic correctness of the supplied Key Block Header;
* lifecycle, authorization, auditing, and destruction of transported keys.

The `clear_key` slice is supplied by the caller. The caller remains responsible
for how that key is generated, stored, protected, and erased outside the
temporary internal buffers owned by this crate.

The ephemeral AES key generated internally by the TR-34 export also exists in
application memory. A PKCS #11 provider can use a temporary session object for
the AES operation, but this does not make the ephemeral key fully
HSM-contained.

When persistent RSA keys are represented by `Pkcs11Key`, the provider can
perform supported operations without reading their private key values into the
application. Whether those keys are actually non-exportable depends on the
token, object attributes, and provisioning process.

Using this crate does not by itself establish compliance with PCI, ANSI, ISO,
card-network, or other payment-security requirements. Production deployments
may require certified HSMs, controlled key ceremonies, dual control, split
knowledge, access controls, audit logging, key lifecycle procedures, and other
operational controls.

## Current limitations

The current implementation deliberately does not attempt to cover all of
TR-34.

Not implemented at this stage:

* TDEA / TDES transport;
* one-pass key transport;
* KRD-side token processing;
* credential-token exchange as a high-level protocol workflow;
* RTKRD generation or replay-state management;
* bind, unbind, and rebind flows;
* higher-level authority unbind / rebind;
* certificate-path construction or trust-anchor management;
* certificate and CRL policy validation;
* automatic TR-31 Key Block Header construction or semantic validation.

The current public operation is therefore best viewed as:

> **Construct a complete KDH-side two-pass AES TR-34 key token from
> already-authorized protocol inputs and provider key handles.**

## Testing and interoperability

The crate test suite separates three different concerns.

### Strict regression tests

The strict path has a frozen complete-token regression vector. This protects
the standards-oriented CMS encoding from accidental changes while
compatibility support evolves.

### Published TR-34 2019 AES vectors

The tests preserve the published Annex B AES fixtures and explicitly document
their inconsistencies, including:

* KeyBlock version / header representation;
* non-CMS `encryptedContent` placement;
* the serialized eight-byte IV;
* recovery of the actual 16-byte IV;
* the different Key Block Header found after decrypting the published
  ciphertext.

### Annex B end-to-end export

A separate public-API integration test exercises `Tr34Profile::AnnexB2019` end
to end and verifies that the intended compatibility choices reach the final
token together.

### PKCS #11 provider compatibility

`paysec-crypto-pkcs11` contains a compile-time integration test against the
actual `export_key_two_pass` API.

This verifies that the PKCS #11 provider supplies all required cryptographic
traits without introducing a dependency from `paysec-tr34` onto a concrete
provider.

The provider's lower-level AES, random-generation, and RSA-signature behavior
is exercised separately against SoftHSM.

A complete SoftHSM TR-34 export is not currently possible because of
SoftHSM's RSA-OAEP SHA-256 parameter limitation.

This separation is intentional: the project keeps **what the standard
publishes**, **what strict CMS requires**, **what the coherent compatibility
profile emits**, and **what individual provider environments can exercise** as
distinct testable concepts.

## Development

From the workspace root:

```text
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo test --workspace --doc
cargo doc --workspace --no-deps --open
```

For this crate only:

```text
cargo test -p paysec-tr34
cargo test -p paysec-tr34 --doc
cargo doc -p paysec-tr34 --no-deps
```

## Further documentation

* [`docs/compatibility.md`](docs/compatibility.md) — detailed rationale for the
  encoding profiles and Annex B interoperability choices.
* Rust API documentation for `TwoPassKeyExportRequest`, `Tr34Profile`, and
  `export_key_two_pass`.
* [`paysec-crypto-pkcs11`](../paysec-crypto-pkcs11/README.md) — PKCS #11
  provider configuration, capabilities, and security model.
* ASC X9 TR 34-2019 — protocol definition, Annex B examples, and normative
  ASN.1 in Annex D.

The TR-34 standard itself is copyrighted material and is not distributed by
this crate.

## License

`paysec-tr34` is part of the `paysec` project and is licensed under the GNU
General Public License Version 3.0 only (`GPL-3.0-only`).

See the repository `LICENSE` file for the complete license terms.

The implementation may reference standards and protocols whose copyrights and
intellectual-property rights belong to their respective standards
organizations. Users are responsible for obtaining any standards documents or
licenses required for their use case.
