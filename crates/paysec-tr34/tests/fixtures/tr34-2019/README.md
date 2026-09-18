# ASC X9 TR 34-2019 Annex B AES fixtures

These fixtures were extracted from the Annex B samples in the supplied
ASC X9 TR 34-2019 document.

Included source material:

- B.2.1.3: sample CA KDH CRL
- B.2.1.5: sample KDH 1 PKCS#12 bundle (certificate extracted)
- B.2.1.7: sample KRD 1 PKCS#12 bundle (certificate and private key extracted)
- B.2.2.2.4: sample AES KeyBlock DER
- B.2.2.3.2: sample AES EnvelopedData DER

The PKCS#12 password specified by Annex B is `TR34`. The private key is
stored here as unencrypted PKCS#8 DER for test-fixture use only.

## Fixture SHA-256

- `aes-enveloped-data.der`: `fb3e8b94bf22c4b456804d7145832315e4366937296c773f5cbc26dd39adbf71`
- `aes-key-block.der`: `eceeedaa129dc583df2ac6a0d68d9b89247ea9e18b005eff4cdb617a5f0e7fc2`
- `ca-kdh.crl.der`: `bb7ada310df4bba76989de3a472469f0c96d3a77737f9c9e99063ba9725c339d`
- `kdh-1-certificate.der`: `2a12ee21a7839b8e79a147848198e6e4e91637fcdf13f65e4c52b630fc3cc360`
- `krd-1-certificate.der`: `db237aac3cb990f51d92ee57d0b60c6c04024de4a05ecd95f83a08c15d839594`
- `krd-1-private-key.der`: `12ba035483f9b0c6fd9c9182dfb9d3f1327e21f49ce46504a0c195985f6f7237`

## Compatibility observations

The files are preserved as published rather than normalized to the strict
encoder behavior.

The Annex B AES KeyBlock sample uses version INTEGER 1 and the sample KBH
encoding rather than the strict Annex D representation used by paysec-tr34.

The Annex B AES EnvelopedData sample encodes an eight-byte OCTET STRING
`0123456789ABCDEF` as the AES-128-CBC algorithm parameter. AES-CBC normally
uses a 16-byte IV, so the conformance test records the sample bytes rather
than treating this as the strict encoder requirement.

Additional local verification also found that the published AES
`encryptedKey` does not decrypt with the supplied KRD 1 private key using
the published OAEP SHA-256 / MGF1-SHA256 parameters. This is recorded as a
sample interoperability issue and is intentionally not asserted by the
initial conformance tests.

Likewise, decrypting the AES encryptedContent using the published AES key
and a zero-extended form of the published eight-byte IV yields the same
sample KeyBlock apart from the KBH: the encrypted sample contains
`A0256K0TB00E0000`, while B.2.2.2.4 publishes `D0256K0AB00E0000`.
Compatibility support should therefore be introduced explicitly rather
than changing the strict default encoding.
