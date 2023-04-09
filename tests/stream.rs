#![cfg(feature = "std")]

use std::io::Cursor;

use base64::Engine;
use magic_crypt::{new_magic_crypt, MagicCryptError, MagicCryptTrait};

fn encrypt_reader_to_writer(mc: impl MagicCryptTrait) -> String {
    let mut output_buffer = Cursor::new([0; 32]);

    mc.encrypt_reader_to_writer(&mut Cursor::new("https://magiclen.org"), &mut output_buffer)
        .unwrap();

    let c = output_buffer.position();
    let output = output_buffer.into_inner();

    base64::engine::general_purpose::STANDARD.encode(&output[..c as usize])
}

fn decrypt_reader_to_writer(
    mc: impl MagicCryptTrait,
    base64: &str,
) -> Result<String, MagicCryptError> {
    let encrypted_data = base64::engine::general_purpose::STANDARD.decode(base64).unwrap();

    let mut output_buffer = Cursor::new(vec![0; 32]);

    mc.decrypt_reader_to_writer(&mut Cursor::new(encrypted_data), &mut output_buffer)?;

    let c = output_buffer.position();
    let mut output = output_buffer.into_inner();
    output.truncate(c as usize);

    Ok(String::from_utf8(output)?)
}

#[test]
fn crypt_64_reader_writer() {
    let mc = new_magic_crypt!("magickey", 64);

    let base64 = encrypt_reader_to_writer(mc);

    assert_eq!("hnVcTXXaXO77Adc9jhnUV5AhIFq1SQNO", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 64);

    assert_eq!("https://magiclen.org", decrypt_reader_to_writer(mc, &base64).unwrap());

    let mc = new_magic_crypt!("xxxxxxxx", 64);

    assert!(decrypt_reader_to_writer(mc, &base64).is_err());
}

#[test]
fn crypt_128_reader_writer() {
    let mc = new_magic_crypt!("magickey", 128);

    let base64 = encrypt_reader_to_writer(mc);

    assert_eq!("4tk0QoLU++c2TiZ/hke5YY9wHn2pluNIXaj8L3khj3s=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 128);

    assert_eq!("https://magiclen.org", decrypt_reader_to_writer(mc, &base64).unwrap());

    let mc = new_magic_crypt!("xxxxxxxx", 128);

    assert!(decrypt_reader_to_writer(mc, &base64).is_err());
}

#[test]
fn crypt_192_reader_writer() {
    let mc = new_magic_crypt!("magickey", 192);

    let base64 = encrypt_reader_to_writer(mc);

    assert_eq!("IccS4yndkkxev4eoy6FNlZxkz9YbxsEp5AzWiqzBDBQ=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 192);

    assert_eq!("https://magiclen.org", decrypt_reader_to_writer(mc, &base64).unwrap());

    let mc = new_magic_crypt!("xxxxxxxx", 192);

    assert!(decrypt_reader_to_writer(mc, &base64).is_err());
}

#[test]
fn crypt_256_reader_writer() {
    let mc = new_magic_crypt!("magickey", 256);

    let base64 = encrypt_reader_to_writer(mc);

    assert_eq!("jWEPYLTECqGvWJbdlRGeZIupoLX8N9DYZIUKMRp/OQY=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 256);

    assert_eq!("https://magiclen.org", decrypt_reader_to_writer(mc, &base64).unwrap());

    let mc = new_magic_crypt!("xxxxxxxx", 256);

    assert!(decrypt_reader_to_writer(mc, &base64).is_err());
}
