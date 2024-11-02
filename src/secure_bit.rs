use core::convert::TryFrom;

/// How secure does your encryption need to be?
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecureBit {
    Bit64,
    #[default]
    Bit128,
    Bit192,
    Bit256,
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
