MagicCrypt
====================

[![CI](https://github.com/magiclen/rust-magiccrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rust-magiccrypt/actions/workflows/ci.yml)

MagicCrypt is a Java/PHP/NodeJS/Rust library to encrypt/decrpyt strings, files, or data, using Data Encryption Standard(DES) or Advanced Encryption Standard(AES) algorithms. It supports CBC block cipher mode, PKCS5 padding and 64, 128, 192 or 256-bits key length.

## For Rust

### Example

```rust
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

let mc = new_magic_crypt!("magickey", 256);

let base64 = mc.encrypt_str_to_base64("http://magiclen.org");

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
```

## Change the Buffer Size

The default buffer size for the `encrypt_reader_to_writer` method and the `decrypt_reader_to_writer` method is 4096 bytes. If you want to change that, you can use the `encrypt_reader_to_writer2` method or the `decrypt_reader_to_writer2` method, and define a length explicitly.

For example, to change the buffer size to 256 bytes,

```rust
use std::io::Cursor;

use base64::Engine;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use magic_crypt::generic_array::typenum::U256;

let mc = new_magic_crypt!("magickey", 256);

let mut reader = Cursor::new("http://magiclen.org");
let mut writer = Vec::new();

mc.encrypt_reader_to_writer2::<U256>(&mut reader, &mut writer).unwrap();

let base64 = base64::engine::general_purpose::STANDARD.encode(&writer);

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
```

## No Std

Disable the default features to compile this crate without std.

```toml
[dependencies.magic-crypt]
version = "*"
default-features = false
```

### Crates.io

https://crates.io/crates/magic-crypt

### Documentation

https://docs.rs/magic-crypt

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