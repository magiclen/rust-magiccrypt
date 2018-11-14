/// This macro provides a convenient way to create a MagicCrypt instance.
#[macro_export]
macro_rules! new_magic_crypt {
    ( $key:expr ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128, None::<String>)
        }
    };
    ( $key:expr, 64 ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit64, None::<String>)
        }
    };
    ( $key:expr, 128 ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128, None::<String>)
        }
    };
    ( $key:expr, 192 ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit192, None::<String>)
        }
    };
    ( $key:expr, 256 ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit256, None::<String>)
        }
    };
    ( $key:expr, 64 ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit64, None::<String>)
        }
    };
    ( $key:expr, 64, $iv:expr ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit64, Some($iv))
        }
    };
    ( $key:expr, 128, $iv:expr ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128, Some($iv))
        }
    };
    ( $key:expr, 192, $iv:expr ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit192, Some($iv))
        }
    };
    ( $key:expr, 256, $iv:expr ) => {
        {
            use ::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit256, Some($iv))
        }
    };
}