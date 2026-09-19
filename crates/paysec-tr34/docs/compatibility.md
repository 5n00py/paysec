# TR-34 Compatibility Profiles

`paysec-tr34` distinguishes between standards-oriented encoding and
interoperability behavior observed in published TR-34 examples and
implementations.

The public API exposes coherent profiles rather than individual encoding
quirks. Internally, profile behavior may be decomposed into independent
encoding decisions so that vendor- or implementation-specific profiles can
be represented without coupling unrelated differences.

## Strict profile

The `Strict` profile follows the normative TR-34 ASN.1 definitions and the
underlying CMS and PKCS specifications where the informative examples in
Annex B disagree with them.

In particular, the strict profile uses:

| Detail | Strict behavior |
| --- | --- |
| KeyBlock version | `INTEGER 0` |
| KeyBlock header | Bare `OCTET STRING` |
| EncryptedContent placement | CMS `EncryptedContentInfo` sibling |
| AES-CBC IV | 16 bytes |
| RSAES-OAEP parameters | PKCS#1 tagged parameters |
| SignedAttributes ordering | DER canonical SET OF ordering |
| SignedData version | CMS-derived version (`3` for `id-envelopedData`) |
| Signature algorithm identifier | `sha256WithRSAEncryption` |
| KDH CRL | Included for complete two-pass key export |

This profile is the default.

## Annex B 2019 compatibility profile

The `AnnexB2019` profile is intended for interoperability with the encoding
family demonstrated by the ASC X9 TR 34-2019 Annex B examples and compatible
implementations.

It does not imply reproducing known cryptographic defects in published test
vectors. In particular, AES-CBC continues to use a 16-byte IV.

Expected compatibility behavior:

| Detail | Annex B 2019 behavior |
| --- | --- |
| KeyBlock version | `INTEGER 1` |
| KeyBlock header | `id-data` Attribute wrapper |
| EncryptedContent placement | Inside the content-encryption SEQUENCE |
| AES-CBC IV | 16 bytes |
| RSAES-OAEP parameters | Annex B sample representation |
| SignedAttributes ordering | Annex B sample order |
| SignedData version | `INTEGER 1` |
| Signature algorithm identifier | `rsaEncryption` |
| KDH CRL | Included unless a later integration profile specifies otherwise |

## Published Annex B inconsistencies

Annex B is informative and contains several encodings that disagree either
with the normative ASN.1 definitions or with the cryptographic values in the
same test vectors.

### AES KeyBlock

Annex D defines:

- KeyBlock version `v1(0)`.
- `KeyBlockHeader ::= OCTET STRING`.

The AES KeyBlock in Annex B.2.2.2.4 instead encodes version `1` and wraps the
KBH in an `id-data` Attribute.

The published AES KeyBlock contains:

`D0256K0AB00E0000`

### AES EnvelopedData IV

Annex B.2.2.3.2 serializes the AES-CBC IV parameter as only eight bytes:

`0123456789ABCDEF`

AES-CBC requires a 16-byte IV.

The published ephemeral AES key, first plaintext block, and first ciphertext
block allow the actual IV used to generate the ciphertext to be recovered
from CBC:

`IV = AES^-1_K(C1) XOR P1`

The recovered IV is:

`0123456789ABCDEF0000000000000000`

The conformance tests derive this value rather than treating the trailing
zero bytes as an assumption.

### AES EnvelopedData plaintext

Decrypting the complete published AES ciphertext using the recovered IV
produces a valid 133-byte KeyBlock followed by eleven bytes of PKCS#7
padding.

The decrypted KeyBlock contains:

`A0256K0TB00E0000`

rather than the independently published AES KeyBlock header:

`D0256K0AB00E0000`

The B.2.2.3.2 encrypted sample therefore was not generated from the
B.2.2.2.4 AES KeyBlock fixture.

### EncryptedContent placement

The Annex B EnvelopedData encoding places `encryptedContent` inside the
SEQUENCE used for the content-encryption algorithm.

This differs from normal CMS `EncryptedContentInfo`, where
`contentEncryptionAlgorithm` and `encryptedContent` are sibling fields.

IBM CCA/ICSF documents this as an interoperability difference and supports
both TR-34-2012-style and TR-34-2019-style placement.

### SignedAttributes ordering

Annex B presents SignedAttributes in a fixed example order rather than the
canonical DER SET OF ordering used by the strict profile.

IBM CCA/ICSF exposes separate behavior for standards-oriented and
example-style SignedAttributes ordering, confirming that both forms are
encountered in deployed integrations.

### SignedData version

The B.9 description specifies SignedData version `3`, consistent with CMS
when `eContentType` is `id-envelopedData`.

The actual B.9.1 sample token encodes version `1`.

### Signature algorithm identifier

B.9 prose specifies `sha256WithRSAEncryption`.

The B.9 pseudo-ASN.1 and the actual sample token use `rsaEncryption` in
SignerInfo instead.

Public AWS TR-34 sample code also uses `rsaEncryption` while producing an
RSA PKCS#1 v1.5 SHA-256 signature.

## Interoperability references

The compatibility model is informed by three classes of evidence:

| Source | Role |
| --- | --- |
| ASC X9 TR 34-2019 Annex D | Normative TR-34 ASN.1 |
| ASC X9 TR 34-2019 Annex B | Published interoperability examples |
| IBM CCA / ICSF | Production interoperability behavior |
| AWS Payment Cryptography samples | Public implementation reference |

IBM is particularly useful because its documented TR-34 controls expose
independent choices for EncryptedContent placement and SignedAttributes
ordering. This supports keeping those decisions independent internally even
though the public `paysec-tr34` API exposes one coherent profile.

## Internal policy model

Profiles should map internally to independent encoding decisions. These
details are intentionally not public API.

Conceptually:

```text
Tr34Profile
    |
    +-- KeyBlock version
    +-- KeyBlock header representation
    +-- EncryptedContent layout
    +-- OAEP parameter encoding
    +-- SignedAttributes ordering
    +-- SignedData version
    +-- SignatureAlgorithm encoding
````

A future vendor or integration profile should be added only when its behavior
is supported by implementation documentation, test vectors, or verified
interoperability evidence.
