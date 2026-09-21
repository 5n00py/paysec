# PKCS #11 SoftHSM integration tests

The integration tests in this directory exercise `paysec-crypto-pkcs11`
against a real PKCS #11 implementation.

They use SoftHSM2 as a software-backed PKCS #11 token. Token
initialization and persistent key provisioning are intentionally performed
outside the `paysec-crypto-pkcs11` crate. The provider connects to an
existing token and uses already-provisioned key objects.

Some tests also exercise temporary PKCS #11 session objects created by the
provider from host-resident ephemeral AES key material. These objects are
non-persistent and are destroyed immediately after the cryptographic
operation.

The SoftHSM tests are ignored by default and therefore do not require
SoftHSM for a normal `cargo test` run.

## Prerequisites

On Debian, install SoftHSM2 and the OpenSC PKCS #11 tools:

```bash
sudo apt install softhsm2 opensc
```

The SoftHSM PKCS #11 module is commonly located at:

```text
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

The exact location depends on the system. It can be found with:

```bash
dpkg -L libsofthsm2 | grep '/libsofthsm2\.so$'
```

## SoftHSM configuration

This setup keeps the development token store under the user's home
directory.

Create the token and configuration directories:

```bash
mkdir -p "$HOME/.local/share/softhsm2/tokens"
mkdir -p "$HOME/.config/softhsm2"
```

Create:

```text
~/.config/softhsm2/softhsm2.conf
```

with:

```text
directories.tokendir = /home/YOUR_USERNAME/.local/share/softhsm2/tokens
objectstore.backend = file
log.level = INFO
slots.removable = false
```

Replace `YOUR_USERNAME` with the local username.

SoftHSM uses the `SOFTHSM2_CONF` environment variable to select this
configuration.

## Test environment

Copy the example environment file:

```bash
cp crates/paysec-crypto-pkcs11/tests/.env.example \
   crates/paysec-crypto-pkcs11/tests/.env
```

Adjust the PKCS #11 module path if required.

Load the variables into the current shell:

```bash
set -a
. crates/paysec-crypto-pkcs11/tests/.env
set +a
```

The `.env` file is intended only for the local integration-test
environment and must not be committed.

## Initialize the test token

Initialize a new SoftHSM token:

```bash
softhsm2-util \
    --init-token \
    --free \
    --label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --so-pin "$PAYSEC_PKCS11_SO_PIN" \
    --pin "$PAYSEC_PKCS11_USER_PIN"
```

The configured credentials are test credentials only and must not be
reused for real PKCS #11 tokens or HSMs.

The available tokens can be inspected with:

```bash
softhsm2-util --show-slots
```

## Provision the AES test keys

The integration tests use fixed AES-128 keys so that cryptographic
results can be checked against published known-answer vectors.

The test token contains the following persistent AES keys:

```text
ID:    10
Label: paysec-aes-128
Usage: AES block-cipher known-answer test

ID:    11
Label: paysec-aes-nist-128
Usage: AES-CBC and AES-CMAC known-answer tests
```

Persistent provisioning is deliberately performed outside the Rust
integration tests.

### AES block-cipher test key

The AES block-cipher test uses the following AES-128 key:

```text
000102030405060708090a0b0c0d0e0f
```

Create the temporary key file:

```bash
printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' \
    > /tmp/paysec-aes-128.bin
```

Import it into the token:

```bash
pkcs11-tool \
    --module "$PAYSEC_PKCS11_MODULE" \
    --token-label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --pin env:PAYSEC_PKCS11_USER_PIN \
    --write-object /tmp/paysec-aes-128.bin \
    --type secrkey \
    --key-type AES:16 \
    --id 10 \
    --label "paysec-aes-128" \
    --usage-decrypt \
    --private \
    --sensitive
```

Remove the temporary clear-key file:

```bash
rm /tmp/paysec-aes-128.bin
```

### AES NIST test key

The AES-CBC integration test uses the following AES-128 key:

```text
2b7e151628aed2a6abf7158809cf4f3c
```

This key is also used by the AES-CMAC known-answer vectors and can
therefore be reused by the CMAC integration tests.

Create the temporary key file:

```bash
printf '\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c' \
    > /tmp/paysec-aes-nist-128.bin
```

Import it into the token:

```bash
pkcs11-tool \
    --module "$PAYSEC_PKCS11_MODULE" \
    --token-label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --pin env:PAYSEC_PKCS11_USER_PIN \
    --write-object /tmp/paysec-aes-nist-128.bin \
    --type secrkey \
    --key-type AES:16 \
    --id 11 \
    --label "paysec-aes-nist-128" \
    --usage-decrypt \
    --usage-sign \
    --private \
    --sensitive
```

Remove the temporary clear-key file:

```bash
rm /tmp/paysec-aes-nist-128.bin
```

## Provision the RSA test key pair

The RSA integration tests use a 2048-bit RSA key pair generated directly
inside the SoftHSM token.

The public and private key objects share the same PKCS #11 object ID and
label:

```text
ID:    20
Label: paysec-rsa-2048
Usage: RSA-OAEP and RSA signature integration tests
```

Generate the key pair:

```bash
pkcs11-tool \
    --module "$PAYSEC_PKCS11_MODULE" \
    --token-label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --pin env:PAYSEC_PKCS11_USER_PIN \
    --keypairgen \
    --key-type RSA:2048 \
    --id 20 \
    --label "paysec-rsa-2048" \
    --usage-decrypt \
    --usage-sign
```

The key pair is generated inside the token. The private key material is
therefore not imported into or exported from the test application.

The shared object ID allows `Pkcs11Key::by_id([0x20])` to represent the
logical RSA key pair. The cryptographic operation determines which
PKCS #11 object is resolved:

```text
RSA encryption / verification -> public key object
RSA decryption / signing      -> private key object
```

## Inspect the provisioned keys

Inspect the AES secret-key objects:

```bash
pkcs11-tool \
    --module "$PAYSEC_PKCS11_MODULE" \
    --token-label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --pin env:PAYSEC_PKCS11_USER_PIN \
    --list-objects \
    --type secrkey
```

The token should contain both persistent AES keys:

```text
ID:    10
Label: paysec-aes-128

ID:    11
Label: paysec-aes-nist-128
```

Because the AES keys are provisioned as sensitive, `pkcs11-tool` may
report `CKR_ATTRIBUTE_SENSITIVE` when attempting to read their values.
This is expected and does not prevent the keys from being used for
cryptographic operations.

Inspect the RSA public key:

```bash
pkcs11-tool \
    --module "$PAYSEC_PKCS11_MODULE" \
    --token-label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --pin env:PAYSEC_PKCS11_USER_PIN \
    --list-objects \
    --type pubkey
```

Inspect the RSA private key:

```bash
pkcs11-tool \
    --module "$PAYSEC_PKCS11_MODULE" \
    --token-label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --pin env:PAYSEC_PKCS11_USER_PIN \
    --list-objects \
    --type privkey
```

Both RSA objects should have:

```text
ID:    20
Label: paysec-rsa-2048
```

The private key value is not readable from the token. Cryptographic
operations using the private key are performed inside the PKCS #11
implementation.

Persistent provisioning is deliberately not performed by the Rust
integration tests. A production PKCS #11 application may not have
permission to create, import, modify, or delete persistent key objects,
and `paysec-crypto-pkcs11` follows that operational model.

Temporary session objects created internally for ephemeral AES
operations are a separate mechanism. They use `CKA_TOKEN = false`,
exist only for the operation, and are destroyed immediately afterward.

## Run the tests

Normal crate tests do not require SoftHSM:

```bash
cargo test -p paysec-crypto-pkcs11
```

This also compiles the TR-34 compatibility test. That test does not
connect to SoftHSM; compilation itself verifies that `Pkcs11Provider`
satisfies the cryptographic trait requirements of the current
`paysec-tr34` API.

After loading the integration-test environment, run the SoftHSM tests
explicitly:

```bash
cargo test \
    -p paysec-crypto-pkcs11 \
    --test softhsm \
    -- --ignored --test-threads=1
```

The SoftHSM integration suite covers:

* AES block encryption and decryption using a known-answer vector
* AES-CBC using a persistent NIST AES-128 key
* AES-CBC using a host-resident key imported as a temporary session object
* AES-CMAC using an RFC 4493 known-answer vector
* random-byte generation using the token RNG
* missing-key handling
* rejection of non-block-aligned AES-CBC input
* RSA PKCS#1 v1.5 SHA-256 signing and verification
* rejection of a signature when the signed message is modified

The temporary AES-key test does not require an additional provisioned
object. The provider creates a non-persistent AES session object from the
test key, performs the CBC operation, and destroys the object before the
operation completes.

The random-byte test does not require a key object; it exercises the
token's `C_GenerateRandom` capability directly.

The integration tests are run serially because PKCS #11 module and
session lifecycle management is currently intentionally simple.

## TR-34 compatibility

`paysec-crypto-pkcs11` satisfies the cryptographic provider requirements
of the current TR-34 two-pass key-export implementation:

```text
RandomBytes
AesCbc<[u8]>
RsaOaepSha256Encrypt<Pkcs11Key>
RsaPkcs1v15Sha256Sign<Pkcs11Key>
```

The `tr34_compile.rs` integration test verifies this against the actual
`paysec-tr34` public API at compile time.

An end-to-end TR-34 SoftHSM test is not currently possible because of the
RSA-OAEP limitation described below.

## RSA-OAEP-SHA256 limitation

`paysec-crypto-pkcs11` implements `RsaOaepSha256Encrypt` using
`CKM_RSA_PKCS_OAEP` with:

```text
OAEP hash: SHA-256
MGF:       MGF1-SHA256
Label:     empty
```

The SoftHSM implementation used by this test environment restricts
`CKM_RSA_PKCS_OAEP` to SHA-1 and MGF1-SHA1.

SoftHSM therefore cannot exercise the `RsaOaepSha256Encrypt`
implementation or run the complete TR-34 flow.

The provider implementation is intentionally not weakened to SHA-1 to
accommodate SoftHSM, because that would violate the
`RsaOaepSha256Encrypt` contract defined by `paysec-crypto`.

The RSA key pair remains useful for the RSA PKCS#1 v1.5 SHA-256 signing
and verification integration tests.

A PKCS #11 HSM supporting the required SHA-256 OAEP parameter profile
can use the same provider implementation without changes.
