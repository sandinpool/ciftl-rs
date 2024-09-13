use crate::encoding::hex::HexEncoding;
use crate::encoding::Encoding;
use crate::etc::ByteArray;
use ring::digest;
use ring::digest::SHA1_OUTPUT_LEN;

use crate::hash::Hasher;

pub const SHA1_OUTPUT_LENGTH: usize = SHA1_OUTPUT_LEN;

/// Sha1哈希操作
pub struct Sha1Hasher {
    m_ctx: digest::Context,
}

impl Sha1Hasher {
    pub fn new() -> Sha1Hasher {
        Sha1Hasher {
            m_ctx: digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        }
    }
}

impl Hasher<SHA1_OUTPUT_LEN> for Sha1Hasher {
    /// 计算一个消息的哈希值
    fn update_message(&mut self, message: &str) -> () {
        self.m_ctx.update(message.as_bytes());
    }
    /// 计算一个字节数组的哈希值
    fn update_bytes(&mut self, vec: &[u8]) -> () {
        self.m_ctx.update(vec);
    }
    /// 获取结果
    fn finalize(&self) -> ByteArray<SHA1_OUTPUT_LENGTH> {
        let res = self.m_ctx.clone().finish();
        // 获取引用的结果
        let ref_res = res.as_ref();
        let mut res = ByteArray::<SHA1_OUTPUT_LENGTH>::new();
        for i in 0..SHA1_OUTPUT_LENGTH {
            res[i] = ref_res[i];
        }
        res
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sha1_operation() {
        let hexe = HexEncoding::default();
        let mut sha1_hasher = Sha1Hasher::new();
        // 123456
        sha1_hasher.update_message("123456");
        let res = sha1_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!("7C4A8D09CA3762AF61E59520943DC26494F8941B".to_string(), res);
        // 12345678910
        sha1_hasher.update_message("78910");
        let res = sha1_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!("9048EAD9080D9B27D6B2B6ED363CBF8CCE795F7F".to_string(), res);
    }
}
