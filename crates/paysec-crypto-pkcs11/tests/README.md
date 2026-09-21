# PKCS #11 SoftHSM integration tests

The integration tests in this directory exercise `paysec-crypto-pkcs11`
against a real PKCS #11 implementation.

They use SoftHSM2 as a software-backed PKCS #11 token. Token
initialization and key provisioning are intentionally performed outside
the `paysec-crypto-pkcs11` crate. The provider only connects to an
existing token and uses already-provisioned key objects.

The tests are ignored by default and therefore do not require SoftHSM
for a normal `cargo test` run.

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

Create the token directory:

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

## Provision the AES test key

The AES block-cipher integration test uses a fixed AES-128 key so that
the result can be checked against a known-answer vector.

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

Inspect the provisioned object:

```bash
pkcs11-tool \
    --module "$PAYSEC_PKCS11_MODULE" \
    --token-label "$PAYSEC_PKCS11_TOKEN_LABEL" \
    --pin env:PAYSEC_PKCS11_USER_PIN \
    --list-objects \
    --type secrkey
```

The token should contain an AES secret key with:

```text
ID:    10
Label: paysec-aes-128
```

Provisioning is deliberately not performed by the Rust integration
test. A production PKCS #11 application may not have permission to
create, import, modify, or delete key objects, and
`paysec-crypto-pkcs11` follows that operational model.

## Run the integration test

Normal crate tests do not require SoftHSM:

```bash
cargo test -p paysec-crypto-pkcs11
```

After loading the integration-test environment, run the SoftHSM test
explicitly:

```bash
cargo test \
    -p paysec-crypto-pkcs11 \
    --test softhsm \
    -- --ignored --test-threads=1
```

The AES test checks the fixed AES-128 known-answer vector and resolves
the provisioned key both by PKCS #11 object ID and by label.

The integration tests are run serially because PKCS #11 module and
session lifecycle management is currently intentionally simple.
