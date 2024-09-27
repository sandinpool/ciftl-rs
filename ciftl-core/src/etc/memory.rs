use std::convert::AsRef;
use std::fmt;
use std::ops;
use std::ops::Deref;
use std::ops::DerefMut;

use crate::*;

pub type ByteVector = Vec<u8>;

/// ByteArrray是一个定长的字节容器
#[derive(Debug, Clone)]
pub struct ByteArray<const N: usize>([u8; N]);

impl<const N: usize> ByteArray<N> {
    pub fn new() -> ByteArray<N> {
        ByteArray::<N>([0; N])
    }
}

impl<const N: usize> Default for ByteArray<N> {
    fn default() -> Self {
        ByteArray::<N>([0x00; N])
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
        &self.0
    }
}

impl<const N: usize> DerefMut for ByteArray<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> PartialEq for ByteArray<N> {
    fn eq(&self, other: &Self) -> bool {
        return self.0 == other.0;
    }
}

impl<const N: usize> From<&[u8; N]> for ByteArray<N> {
    fn from(value: &[u8; N]) -> Self {
        ByteArray::<N>(*value)
    }
}

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    fn from(value: [u8; N]) -> Self {
        ByteArray::<N>(value)
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

    fn index(&self, index: usize) -> &Self::Output {
        &self.0.as_slice()[index]
    }
}

impl<const N: usize> ops::IndexMut<usize> for ByteArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0.as_mut_slice()[index]
    }
}

/// 内存获取器，用于不断从一块内存中获取数据直到结束
pub struct MemoryTaker<'a> {
    mem: &'a [u8],
    idx: usize,
    length: usize,
}

impl<'a> MemoryTaker<'a> {
    pub fn new(src: &'a [u8]) -> MemoryTaker {
        MemoryTaker {
            mem: src,
            idx: 0,
            length: src.len(),
        }
    }

    pub fn take(&mut self, dst: &mut [u8]) -> Result<&mut Self> {
        let need_length = dst.len();
        if self.idx + need_length > self.length {
            return Err(MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT.clone());
        }
        memcpy(dst, &self.mem[self.idx..self.idx + need_length])?;
        self.idx += need_length;
        Ok(self)
    }

    pub fn take_all(&mut self) -> Result<ByteVector> {
        if self.idx >= self.length {
            return Err(MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT.clone());
        }
        let res = self.mem[self.idx..].to_vec();
        self.idx = self.length;
        Ok(res)
    }
}

/// 内存拷贝
pub fn memcpy(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() != src.len() {
        return Err(SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH.clone());
    }
    dst.copy_from_slice(src);
    Ok(())
}

/// 内存异或
pub fn xor(src1: &[u8], src2: &[u8]) -> Result<ByteVector> {
    if src1.len() != src2.len() {
        return Err(TWO_MEMORY_HAS_DIFFERENT_LENGTH_WHEN_XOR_OPERATION.clone());
    }
    let target_len = src1.len();
    let mut res = vec![0x00; target_len];
    for i in 0..target_len {
        res[i] = src1[i] ^ src2[i];
    }
    Ok(res)
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

    #[test]
    fn test_memory_taker() {
        let v = b"123456789".to_vec();
        let mut mt = MemoryTaker::new(&v);
        let mut v1: Vec<u8> = vec![0u8; 2];
        let mut v2 = vec![0u8; 3];
        let v3 = mt
            .take(&mut v1)
            .unwrap()
            .take(&mut v2)
            .unwrap()
            .take_all()
            .unwrap();
        assert_eq!(v1, b"12".to_vec());
        assert_eq!(v2, b"345".to_vec());
        assert_eq!(v3, b"6789".to_vec());
        let mut v1: Vec<u8> = vec![0u8; 2];
        assert!(mt.take(&mut v1).is_err());
    }
}
