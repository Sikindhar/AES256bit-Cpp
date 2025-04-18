# AES-256 Encryption/Decryption Implementation

A pure C++ implementation of the Advanced Encryption Standard (AES-256) algorithm without any external cryptographic libraries.

## Overview

This project implements AES-256 bit encryption and decryption from scratch in C++. It's designed as a learning tool to understand the internals of AES encryption while providing a functional encryption/decryption utility. The implementation includes:

- Complete AES-256 encryption and decryption
- CBC (Cipher Block Chaining) mode of operation
- PKCS#7 padding scheme
- Command-line interface for text encryption

## Features

- **Pure C++ Implementation**: No external cryptographic libraries required
- **AES-256 Support**: Uses 256-bit keys (32 bytes) for maximum security
- **CBC Mode**: Implements Cipher Block Chaining for better security than ECB mode
- **PKCS#7 Padding**: Standard padding scheme for handling variable-length messages
- **User-Friendly Interface**: Simple command-line interface for text input
- **Customizable**: Default key that can be easily modified in the code

## How It Works

The implementation follows the AES standard with the following components:

1. **SubBytes**: Non-linear substitution using the AES S-box
2. **ShiftRows**: Transposition step where bytes are shifted within rows
3. **MixColumns**: Linear mixing operation for diffusion
4. **AddRoundKey**: Each byte is combined with the round key using XOR
5. **Key Expansion**: The initial key is expanded to derive round keys

For decryption, the inverse operations are performed in reverse order.

## Usage

Compile the program:

```bash
g++ AesMain.cpp -o AesMain
```

Run the program:

```bash
./AesMain
```

The program will:
1. Prompt you to enter text to encrypt
2. Encrypt the text using AES-256-CBC with the default key
3. Display the encrypted text in hexadecimal format
4. Automatically decrypt the text back to verify correct operation
5. Display the decrypted text

## Customization

To change the encryption key, modify the `key` vector in the `main()` function:

```cpp
std::vector<uint8_t> key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
```

## Security Notes

This implementation was created primarily for educational purposes. While it follows the AES standard, for production applications consider using established cryptographic libraries that:

- Have undergone security audits
- Implement side-channel attack protections
- Provide secure key management
- Are regularly updated to address vulnerabilities

## Learning Resources

If you're interested in learning more about AES encryption, check out these resources:

- [NIST AES Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
- [Rijndael S-box](https://en.wikipedia.org/wiki/Rijndael_S-box)
- [Understanding AES Mix Columns Transformation](https://www.angelfire.com/biz7/atleast/mix_columns.pdf)

## Contributing

Feel free to submit issues or pull requests if you find bugs or have suggestions for improvements.

## License

MIT License - feel free to use and modify as needed.