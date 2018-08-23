#[macro_use]
extern crate magic_crypt;

use magic_crypt::MagicCrypt;

#[test]
fn crypt_128() {
    let mut mc: MagicCrypt = new_magic_crypt!("magickey", 128);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_192() {
    let mut mc: MagicCrypt = new_magic_crypt!("magickey", 192);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_256() {
    let mut mc: MagicCrypt = new_magic_crypt!("magickey", 256);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}