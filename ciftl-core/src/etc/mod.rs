use std::fmt;
use std::ops;
use std::ops::Deref;
use std::convert::AsRef;

pub mod error;
pub type ByteVector = Vec<u8>;

#[derive(Debug)]
pub struct ByteArray<const N: usize>([u8; N]);

impl<const N: usize> ByteArray<N> {
    pub fn new() -> ByteArray<N> {
        ByteArray::<N>([0; N])
    }
}

impl<const N: usize> AsRef<[u8]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Deref for ByteArray<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<const N: usize> PartialEq for ByteArray<N> {
    fn eq(&self, other: &Self) -> bool {
        return self.0 == other.0;
    }
}

impl<const N: usize> From<&[u8;N]> for ByteArray<N> {
    fn from(value: &[u8;N]) -> Self {
        ByteArray::<N>(*value)
    }
}

impl<const N: usize> fmt::Display for ByteArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<const N: usize> ops::BitXor for ByteArray<N> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut res = self;
        for i in 0..N {
            res.0[i] = res.0[i] ^ rhs.0[i];
        }
        res
    }
}

impl<const N: usize> ops::Index<usize> for ByteArray<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output
    {
        &self.0.as_slice()[index]
    }
}

impl<const N: usize> ops::IndexMut<usize> for ByteArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output
    {
        &mut self.0.as_mut_slice()[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let a = ByteArray::<4>::from(&[0x12, 0x43, 0x56, 0x87]);
        let b = ByteArray::<4>::from(&[0x75, 0x4A, 0xB1, 0xC9]);
        let res = a ^ b;
        assert_eq!(res.as_ref(), &[0x67, 0x09, 0xE7, 0x4E]);
        println!("Res: {}", res);
    }
}