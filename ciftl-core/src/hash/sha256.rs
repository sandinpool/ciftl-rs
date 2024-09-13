use crate::encoding::hex::HexEncoding;
use crate::encoding::Encoding;
use crate::etc::ByteArray;
use ring::digest;
use ring::digest::SHA256_OUTPUT_LEN;

use crate::hash::Hasher;

pub const SHA256_OUTPUT_LENGTH: usize = SHA256_OUTPUT_LEN;

/// Sha1哈希操作
pub struct Sha256Hasher {
    m_ctx: digest::Context,
}

impl Sha256Hasher {
    pub fn new() -> Sha256Hasher {
        Sha256Hasher {
            m_ctx: digest::Context::new(&digest::SHA256),
        }
    }
}

impl Hasher<SHA256_OUTPUT_LENGTH> for Sha256Hasher {
    /// 计算一个消息的哈希值
    fn update_message(&mut self, message: &str) -> () {
        self.m_ctx.update(message.as_bytes());
    }
    /// 计算一个字节数组的哈希值
    fn update_bytes(&mut self, vec: &[u8]) -> () {
        self.m_ctx.update(vec);
    }
    /// 获取结果
    fn finalize(&self) -> ByteArray<SHA256_OUTPUT_LENGTH> {
        let res = self.m_ctx.clone().finish();
        // 获取引用的结果
        let ref_res = res.as_ref();
        let mut res = ByteArray::<SHA256_OUTPUT_LENGTH>::new();
        for i in 0..SHA256_OUTPUT_LENGTH {
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
        let mut sha1_hasher = Sha256Hasher::new();
        // 123456
        sha1_hasher.update_message("123456");
        let res = sha1_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!(
            "8D969EEF6ECAD3C29A3A629280E686CF0C3F5D5A86AFF3CA12020C923ADC6C92".to_string(),
            res
        );
        // 12345678910
        sha1_hasher.update_message("78910");
        let res = sha1_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!(
            "63640264849A87C90356129D99EA165E37AA5FABC1FEA46906DF1A7CA50DB492".to_string(),
            res
        );
    }
}
