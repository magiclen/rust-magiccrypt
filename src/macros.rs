/// This macro provides a convenient way to create a `MagicCrypt<bits>` instance or a `MagicCrypt` instance.
#[macro_export]
macro_rules! new_magic_crypt {
    (wrapper $key:expr) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit128, None::<String>)
    };
    (wrapper $key:expr,64) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit64, None::<String>)
    };
    (wrapper $key:expr,128) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit128, None::<String>)
    };
    (wrapper $key:expr,192) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit192, None::<String>)
    };
    (wrapper $key:expr,256) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit256, None::<String>)
    };
    (wrapper $key:expr,64, $iv:expr) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit64, Some($iv))
    };
    (wrapper $key:expr,128, $iv:expr) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit128, Some($iv))
    };
    (wrapper $key:expr,192, $iv:expr) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit192, Some($iv))
    };
    (wrapper $key:expr,256, $iv:expr) => {
        $crate::MagicCrypt::new($key, $crate::SecureBit::Bit256, Some($iv))
    };
    ($key:expr) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt128::new($key, None::<String>)
    }};
    ($key:expr,64) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt64::new($key, None::<String>)
    }};
    ($key:expr,128) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt128::new($key, None::<String>)
    }};
    ($key:expr,192) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt192::new($key, None::<String>)
    }};
    ($key:expr,256) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt256::new($key, None::<String>)
    }};
    ($key:expr,64, $iv:expr) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt64::new($key, Some($iv))
    }};
    ($key:expr,128, $iv:expr) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt128::new($key, Some($iv))
    }};
    ($key:expr,192, $iv:expr) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt192::new($key, Some($iv))
    }};
    ($key:expr,256, $iv:expr) => {{
        use $crate::MagicCryptTrait;

        $crate::MagicCrypt256::new($key, Some($iv))
    }};
}
