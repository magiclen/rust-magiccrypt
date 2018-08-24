#[macro_use]
extern crate magic_crypt;

use magic_crypt::MagicCrypt;

#[test]
fn crypt_64() {
    let mut mc: MagicCrypt = new_magic_crypt!("magickey", 64);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("hnVcTXXaXO77Adc9jhnUV5AhIFq1SQNO", base64);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_128() {
    let mut mc: MagicCrypt = new_magic_crypt!("magickey", 128);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("4tk0QoLU++c2TiZ/hke5YY9wHn2pluNIXaj8L3khj3s=", base64);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_192() {
    let mut mc: MagicCrypt = new_magic_crypt!("magickey", 192);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("IccS4yndkkxev4eoy6FNlZxkz9YbxsEp5AzWiqzBDBQ=", base64);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_256() {
    let mut mc: MagicCrypt = new_magic_crypt!("magickey", 256);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("jWEPYLTECqGvWJbdlRGeZIupoLX8N9DYZIUKMRp/OQY=", base64);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}