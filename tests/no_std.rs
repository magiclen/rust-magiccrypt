#![no_std]

use magic_crypt::new_magic_crypt;

#[test]
fn create_cipher_without_std_prelude() {
    let _ = new_magic_crypt!("magickey", 128);
    let _ = new_magic_crypt!(wrapper "magickey", 256);
}
