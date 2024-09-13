pub mod sha1;
pub mod sha256;
pub mod sha512;

use crate::{etc::ByteVector, ByteArray};

/// 哈希操作
pub trait Hasher<const N: usize> {
    /// 计算一个消息的哈希值
    fn update_message(&mut self, message: &str) -> ();
    /// 计算一个字节数组的哈希值
    fn update_bytes(&mut self, vec: &[u8]) -> ();
    /// 获取结果
    fn finalize(&self) -> ByteArray<N>;
}

pub use sha1::Sha1Hasher;
pub use sha256::Sha256Hasher;
pub use sha512::Sha512Hasher;