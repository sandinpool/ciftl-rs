use ::chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ::chacha20::ChaCha20 as ExChaCha20;

use crate::crypter::{
    CipherAlgorithmBaseTrait, CipherAlgorithmTrait, CipherAlgorithmType, IVKeyNewTrait,
    StreamGenerator, StreamGeneratorMode, StringCrypter,
};
use crate::*;

/// ChaCha20的IV长度
pub const CHACHA20_IV_LENGTH: usize = 12;
/// ChaCha20的Key长度
pub const CHACHA20_KEY_LENGTH: usize = 32;

pub struct ChaCha20CipherAlgorithm {
    m_algo: ExChaCha20,
}

impl CipherAlgorithmBaseTrait for ChaCha20CipherAlgorithm {
    const IV_LENGTH: usize = CHACHA20_IV_LENGTH;
    const KEY_LENGTH: usize = CHACHA20_KEY_LENGTH;
    const CIPHER_ALGORITHM_TYPE: CipherAlgorithmType = CipherAlgorithmType::Stream;
}

impl CipherAlgorithmTrait for ChaCha20CipherAlgorithm {
    fn crypt(&mut self, src_data: &[u8], dst_data: &mut [u8]) -> Result<()> {
        // 这里为了减少拷贝次数，先将src复制到dst中
        memcpy(dst_data, &src_data)?;
        self.m_algo.apply_keystream(dst_data);
        Ok(())
    }
}

impl IVKeyNewTrait for ChaCha20CipherAlgorithm {
    fn new(iv: &[u8], key: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        if iv.len() != Self::IV_LENGTH {
            return Err(CIPHER_ALGORITHM_UNSATISFIED_IV_LENGTH.clone());
        }
        if key.len() != Self::KEY_LENGTH {
            return Err(CIPHER_ALGORITHM_UNSATISFIED_KEY_LENGTH.clone());
        }
        let cipher: ExChaCha20 = ExChaCha20::new(key.into(), iv.into());
        Ok(ChaCha20CipherAlgorithm { m_algo: cipher })
    }
}

#[cfg(test)]
mod tests {

    use crypter::StringCrypterTrait;
    use hash::sha1::Sha1Hasher;
    use hash::sha512::Sha512Hasher;

    use super::*;
    use crate::encoding::hex::HexEncoding;
    use crate::encoding::EncodingTrait;

    #[test]
    fn test_chacha20() {
        let string_crypter = StringCrypter::<ChaCha20CipherAlgorithm>::default();
        let ciphertext = string_crypter.encrypt("123456", "123456").unwrap();
        println!("ciphertext: {ciphertext}");
        let plaintext = string_crypter.decrypt(&ciphertext, "123456").unwrap();
        println!("plaintext: {plaintext}");
        assert_eq!(plaintext, "123456");
    }
}
