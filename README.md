# paysec

`paysec` is a Rust library designed to facilitate the development and testing
of standards related to payment security in retail payment transactions. It
serves as a resource for financial institutions and payment service providers
who require compliance with such standards.

**IMPORTANT DISCLAIMER**: 

The current setup of `paysec` is primarily intended for use in **test
environments** to generate test data. This version is **not recommended for
productive setups**, particularly in scenarios where Hardware Security Modules
(HSMs) are mandated. One key aspect of this limitation is the handling of
random seeds: they must be explicitly provided via the interface, making the
library suitable for deterministic testing. This approach stands in contrast to
the use of strong cryptographic random generators and hardware acceleration for
encryption, which are essential for robust security in production
environments.

You should be aware that while the library offers tools and functionalities
aligned with payment security standards, its utility in production environments
is limited. It is crucial to integrate additional security measures and
hardware capabilities when deploying solutions in a real-world, high-security
context.

## Table of Contents
- [Features](#features)
- [Usage](#usage)
  - [Installation](#installation)
  - [Documentation and Examples](#documentation-and-examples)
- [Related Projects](#related-projects)
  - [PIN Block Web Tool](#pin-block-web-tool)
  - [Key Block Web Tool](#key-block-web-tool)
- [Future Developments](#future-developments)
- [Copyright and License Information](#copyright-and-license-information)

## Features

`paysec` provides functionalities aligned with the payment security standards,
with a primary focus on standards supporting at least AES security levels.
While parts of other versions that are based on TDES (Triple Data Encryption
Standard) might be implemented, they are not the primary focus.

- **ASC X9 TR 31-2018**: Wrap and unwrap cryptographic keys according to the
  TR-31 key block format. Currently version `D` is supported which uses the Key
  Block Binding Method, specifically AES-CMAC to derive the encryption and
  authentication keys from a Key Block Protection Key. This includes
  functionalities for:
  - Generating key blocks with comprehensive header information including key
    usage, algorithm, and mode of use.
  - Supporting multiple optional blocks for extended metadata, such as
    certificates or timestamps.
  - Secure wrapping of cryptographic keys
  - Unwrapping key blocks to retrieve the original cryptographic key and header
    information, ensuring the integrity and authenticity of the key.
  - Finalizing key block headers to comply with block size requirements,
    including automatic padding block insertion.
  - Validating key block structure and header contents against TR-31
    specifications.

- **ISO 9564 Format 4 PIN Block**: Encode and encipher PIN blocks
  using the ISO 9564 format 4 standard. This includes functionalities for:
  - Encoding a Personal Identification Number (PIN) field.
  - Encoding a Primary Account Number (PAN) field for PAN binding of a PIN
    block.
  - Enciphering and deciphering PIN blocks with AES encryption, binding the PIN
    with the PAN for improved security.

- **ISO 9564 Format 3 PIN Block**: Encode and decode PIN blocks using the ISO
  9564 format 3 standard. Note that the functionalities encode and combine
  the PIN and PAN fields but do not ecrypt the resulting PIN block. The
  encoded PIN block would be encrypted in a separate step using algorithm
  like Tripe DES.

## Usage

### Installation

To start using `paysec` in your Rust project, you can install it using Cargo.
Run the following command in your project directory:

```bash 
cargo add paysec 
```

Alternatively, you can manually add the following line to your `Cargo.toml`
file under `[dependencies]`:

```toml 
paysec = "0.1.1" 
```

### Documentation and Examples

`paysec` is equipped with comprehensive high-level documentation comments
across its modules. These comments not only provide detailed explanations of
the functions and their purpose but also include doc test examples that give a
clear impression of how to use the modules effectively.

Additionally, detailed documentation, including API references and more
examples, is available on the Rust docs website. Please visit the `paysec`
documentation page at
[https://docs.rs/paysec/0.1.1/paysec/index.html](https://docs.rs/paysec/0.1.0/paysec/index.html).

## Related Projects

### PIN Block Web Tool 

The [PIN Block Web Tool](https://www.jointech.at/tools/pinblock/index.html) is
a practical application of this library using WebAssembly (Wasm) to provide a
user-friendly interface to generate test data based on ISO 9564 PIN Blocks. The
tools demonstrates the versatility of the `paysec` library and its potential
applications in web-based environments through WebAssembly.

### Key Block Web Tool

The [Key Block Web Tool](https://www.jointech.at/tools/keyblock/index.html)
offers another web interface based on this library to have a more convenient
interface for key block testing and to exemplify the use of the TR-31 module. 

## Future Developments 

`paysec` is actively being developed with plans to include more payment
security features such as:
- Integration with popular payment gateways and protocols.
- An asymmetric keyblock protection formats (TR-34)
- ANSI X9.143 and ISO 20038 extensions for TR-31
- Other TR-31 versions (A, B, C) on request.
- CVV Card Verification Value generation
- EMV related cryptography
- Key Management Web Interface (potentially as separate project based on the
  Wasm binding)
- HSM simulator interface

## Copyright and License Information

`paysec` is licensed under the GNU General Public License Version 3 (GPLv3), a
widely-used free software license that ensures users have the freedom to run,
study, share, and modify the software. The GPLv3 is a copyleft license, which
means that any derivative work created from `paysec` must also be distributed
under the same license terms. For complete license details, refer to the
[LICENSE](LICENSE) file included with the source code, or visit the [GNU
General Public License Version 3, 29 June
2007](https://www.gnu.org/licenses/gpl-3.0.en.html) page.

The copyright of the `paysec` implementation is held by David Schmid
(david.schmid@mailbox.org). 

Also consider the licenses of any related libraries utilized within the
project. Each library may have its own licensing terms, which should be
respected and adhered to.

The implementation of `paysec` may reference various standards and protocols in
the domain of payment security. The copyrights and rights of use for these
underlying standards are held by their respective organizations. Users should
ensure compliance with these standards and respect their intellectual property
rights.

For use cases not related to testing in non-commercial environments, or for any
inquiries regarding alternative licensing arrangements or permissions beyond
the scope of GPLv3, please contact the author, David Schmid, at
david.schmid@mailbox.org.
