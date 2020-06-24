use core::convert::TryFrom;

/// How secure does your encryption need to be?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecureBit {
    Bit64,
    Bit128,
    Bit192,
    Bit256,
}

impl Default for SecureBit {
    fn default() -> Self {
        SecureBit::Bit128
    }
}

impl TryFrom<u16> for SecureBit {
    type Error = &'static str;

    #[inline]
    fn try_from(bit_number: u16) -> Result<Self, Self::Error> {
        Ok(match bit_number {
            64 => SecureBit::Bit64,
            128 => SecureBit::Bit128,
            192 => SecureBit::Bit192,
            256 => SecureBit::Bit256,
            _ => return Err("Unsupported number of bits."),
        })
    }
}
