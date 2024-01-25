# paysec

`paysec` is a Rust library designed to provide standards related to payment
security in retail payment transactions, making it a tool for financial
institutions and payment service providers who require compliance with this
standard.

The initial release focuses on implementing the ISO 9564 format 4 standard for
PIN block encryption and decryption, more standards are planned to be released
here.

## Features

- **ISO 9564 Format 4 PIN Block**: Encode and encipher PIN blocks
  using the ISO 9564 format 4 standard. This includes functionalities for:
  - Encoding a Personal Identification Number (PIN) into a PIN block.
  - Encoding a Primary Account Number (PAN) for secure PIN block generation.
  - Enciphering and deciphering PIN blocks with AES encryption, binding the PIN
    with the PAN for improved security.

## Future Developments 

`paysec` is actively being developed with plans to
include more payment security features such as:
- Additional PIN block formats and encryption standards.
- Integration with popular payment gateways and protocols.
- Keyblock protection with formats such as TR-31 and TR-34
