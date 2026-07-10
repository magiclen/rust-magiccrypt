macro_rules! impl_cipher_secret_traits {
    ($cipher:ident) => {
        impl core::fmt::Debug for $cipher {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.debug_struct(stringify!($cipher)).finish_non_exhaustive()
            }
        }

        impl Drop for $cipher {
            #[inline]
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.key);
                zeroize::Zeroize::zeroize(&mut self.iv);
            }
        }
    };
}

pub mod aes128;
pub mod aes192;
pub mod aes256;
pub mod des64;
