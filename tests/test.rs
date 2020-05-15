#[macro_use]
extern crate magic_crypt;

use magic_crypt::MagicCryptTrait;

#[test]
fn crypt() {
    let mc = new_magic_crypt!("magickey");

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("4tk0QoLU++c2TiZ/hke5YY9wHn2pluNIXaj8L3khj3s=", base64);

    let mc = new_magic_crypt!(wrapper "magickey");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_64() {
    let mc = new_magic_crypt!("magickey", 64);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("hnVcTXXaXO77Adc9jhnUV5AhIFq1SQNO", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 64);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_128() {
    let mc = new_magic_crypt!("magickey", 128);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("4tk0QoLU++c2TiZ/hke5YY9wHn2pluNIXaj8L3khj3s=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 128);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_192() {
    let mc = new_magic_crypt!("magickey", 192);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("IccS4yndkkxev4eoy6FNlZxkz9YbxsEp5AzWiqzBDBQ=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 192);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_256() {
    let mc = new_magic_crypt!("magickey", 256);

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("jWEPYLTECqGvWJbdlRGeZIupoLX8N9DYZIUKMRp/OQY=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 256);

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_64_with_iv() {
    let mc = new_magic_crypt!("magickey", 64, "123456789");

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("Wn9566qFK9g/SD0OPKHAZz3Q/2pAGVbz", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 64, "123456789");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_128_with_iv() {
    let mc = new_magic_crypt!("magickey", 128, "123456789");

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("dQcxpt67DG7+kMiSj+HyjRjjDisy1iZpyvxVJRVKKZ4=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 128, "123456789");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_192_with_iv() {
    let mc = new_magic_crypt!("magickey", 192, "123456789");

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("uqTD7ZesaVEHnlT801hM+T8nqY8lTVWwYoNe1OsMA04=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 192, "123456789");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

#[test]
fn crypt_256_with_iv() {
    let mc = new_magic_crypt!("magickey", 256, "123456789");

    let base64 = mc.encrypt_str_to_base64("https://magiclen.org");

    assert_eq!("ixCZtfFVt01DgOX+WmsqERcd1efq/yVpGLc5SfTVYXc=", base64);

    let mc = new_magic_crypt!(wrapper "magickey", 256, "123456789");

    assert_eq!("https://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}
