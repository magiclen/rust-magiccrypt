MagicCrypt
====================

[![Build Status](https://travis-ci.org/magiclen/rust-magiccrypt.svg?branch=master)](https://travis-ci.org/magiclen/rust-magiccrypt)

MagicCrypt is a Java/PHP/NodeJS/Rust library to encrypt/decrpyt strings, files, or data, using Data Encryption Standard(DES) or Advanced Encryption Standard(AES) algorithms. It supports CBC block cipher mode, PKCS5 padding and 64, 128, 192 or 256-bits key length. If the encrypted data is a string, it will be formatted automatically to Base64.

## For Rust

### Example

```
#[macro_use] extern crate magic_crypt;

use magic_crypt::MagicCrypt;

let mut mc: MagicCrypt = new_magic_crypt!("magickey", 256);

let base64 = mc.encrypt_str_to_base64("http://magiclen.org");

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
```

### Crates.io

https://crates.io/crates/rust-magiccrypt

### Documentation

https://docs.rs/rust-magiccrypt

## For Java

Refer to [https://github.com/magiclen/MagicCrypt](https://github.com/magiclen/MagicCrypt).

## For PHP

Refer to [https://github.com/magiclen/MagicCrypt](https://github.com/magiclen/MagicCrypt).

## For NodeJS

Refer to [https://github.com/magiclen/node-magiccrypt](https://github.com/magiclen/node-magiccrypt).

## License

[Apache-2.0](LICENSE)

## What's More?

Please check out our web page at

https://magiclen.org/aes/