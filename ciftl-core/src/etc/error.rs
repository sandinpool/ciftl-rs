use std::fmt;

use num_derive::FromPrimitive;
// use num_traits::FromPrimitive;

#[derive(FromPrimitive)]
pub enum ErrorCodeEnum {
    /// 错误码起始值
    ErrorCodeBase = 10000,
    /// etc错误
    EtcError = ErrorCodeEnum::ErrorCodeBase as isize + 1 * 1000,
    /// 编码器错误段
    EncodingError = ErrorCodeEnum::ErrorCodeBase as isize + 2 * 1000,
    /// 加密器错误段
    CrypterError = ErrorCodeEnum::ErrorCodeBase as isize + 3 * 1000,
}

#[derive(FromPrimitive)]
pub enum EncodingErrorCodeEnum {
    /// Hex的错误段
    HexEncodingError = ErrorCodeEnum::EncodingError as isize + 1 * 100,
    HexBadDecodingSource,
    /// Bin的错误段
    BinEncodingError = ErrorCodeEnum::EncodingError as isize + 2 * 100,
    /// Base64的错误段
    Base64EncodingError = ErrorCodeEnum::EncodingError as isize + 3 * 100,
    Base64BadDecodingSource,
}

#[derive(FromPrimitive)]
pub enum CrypterErrorCodeEnum {
    /// 密码算法错误段
    CipherAlgorithmError = ErrorCodeEnum::CrypterError as isize + 1 * 100,
    /// 不满足要求的IV长度
    CipherAlgorithmUnsatisfiedIVLength,
    /// 不满足要求的Key长度
    CipherAlgorithmUnsatisfiedKeyLength,
    /// 流生成器错误段
    StreamGeneratorError = ErrorCodeEnum::CrypterError as isize + 2 * 100,
    /// 执行密码操作时失败
    FailedWhenCrypting,
    /// 完成密码操作时失败
    FailedWhenFinalizingCryption,
    /// 刷新缓冲区时失败
    FailedWhenFlushingBuffer,
    /// 流加密器错误段
    StreamCrypterError = ErrorCodeEnum::CrypterError as isize + 3 * 100,
    /// 刷新时当前下标不在缓冲区的最后
    CurrentIndexNotAtTheEndOfBufferWhenFlushing,
    /// 字符串加密器错误段
    StringCrypterError = ErrorCodeEnum::CrypterError as isize + 4 * 100,
    /// 解密后内容无法通过校验
    FailedWhenCheckingCrc32ValueOfDecryptedContent,
    /// 字符串编码时失败
    FailedWhenEncodingString,
    /// 字符串解码时失败
    FailedWhenDecodingString,
    /// 不能对空串加密
    CannotEncryptEmptyString,
}

#[derive(FromPrimitive)]
pub enum EtcErrorCodeEnum {
    /// 容器的错误段
    ContainerError = ErrorCodeEnum::EtcError as isize + 1 * 100,
    /// 拷贝原始内存和目的内存长度不一致
    SrcAndDstMemoryHasDifferentLength,
    /// 进行异或操作的两段内存长度不一致
    TwoMemoryHasDifferentLengthWhenXOROperation,
    /// 内存获取器中的内容长度不足
    MemoryTakerHasNoEnoughContent,
}

/// 错误码
pub type ErrorCode = u32;

/// 错误结构
#[derive(Debug)]
pub struct CiftlError {
    m_error_code: ErrorCode,
    m_error_message: &'static str,
    m_optional_message: Option<String>,
}

impl CiftlError {
    pub const fn new(error_code: ErrorCode, error_message: &'static str) -> CiftlError {
        CiftlError {
            m_error_code: error_code,
            m_error_message: error_message,
            m_optional_message: None,
        }
    }

    pub fn add_opt_mess(&self, optional_message: &str) -> CiftlError {
        let mut error = self.clone();
        error.m_optional_message = Some(optional_message.to_owned());
        error
    }
}

impl fmt::Display for CiftlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref m) = self.m_optional_message {
            write!(
                f,
                "{}::{}::{}",
                self.m_error_code, self.m_error_message, m
            )
        } else {
            write!(
                f,
                "{}::{}",
                self.m_error_code, self.m_error_message
            )
        }
    }
}

impl Clone for CiftlError {
    fn clone(&self) -> Self {
        CiftlError {
            m_error_code: self.m_error_code,
            m_error_message: self.m_error_message,
            m_optional_message: self.m_optional_message.clone(),
        }
    }
}

/// 重定义Resul类型
pub type CiftlResult<T> = Result<T, CiftlError>;

pub mod predef {
    use super::*;

    // 11101
    pub const SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH: &'static CiftlError = &CiftlError::new(
        EtcErrorCodeEnum::SrcAndDstMemoryHasDifferentLength as ErrorCode,
        "拷贝原始内存和目的内存长度不一致",
    );
    // 11102
    pub const TWO_MEMORY_HAS_DIFFERENT_LENGTH_WHEN_XOR_OPERATION: &'static CiftlError =
        &CiftlError::new(
            EtcErrorCodeEnum::TwoMemoryHasDifferentLengthWhenXOROperation as ErrorCode,
            "进行异或操作的两段内存长度不一致",
        );
    // 11103
    pub const MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT: &'static CiftlError = &CiftlError::new(
        EtcErrorCodeEnum::MemoryTakerHasNoEnoughContent as ErrorCode,
        "内存获取器中的内容长度不足",
    );

    // 12101
    pub const HEX_BAD_DECODING_SOURCE: &'static CiftlError = &CiftlError::new(
        EncodingErrorCodeEnum::HexBadDecodingSource as ErrorCode,
        "非法的16进制字符串",
    );
    // 12301
    pub const BASE64_BAD_DECODING_SOURCE: &'static CiftlError = &CiftlError::new(
        EncodingErrorCodeEnum::Base64BadDecodingSource as ErrorCode,
        "非法的Base64字符串",
    );

    // 13101
    pub const CIPHER_ALGORITHM_UNSATISFIED_IV_LENGTH: &'static CiftlError = &CiftlError::new(
        CrypterErrorCodeEnum::CipherAlgorithmUnsatisfiedIVLength as ErrorCode,
        "不满足要求的IV长度",
    );

    // 13102
    pub const CIPHER_ALGORITHM_UNSATISFIED_KEY_LENGTH: &'static CiftlError = &CiftlError::new(
        CrypterErrorCodeEnum::CipherAlgorithmUnsatisfiedKeyLength as ErrorCode,
        "不满足要求的Key长度",
    );

    // 13203
    pub const FAILED_WHEN_FLUSHING_BUFFER: &'static CiftlError = &CiftlError::new(
        CrypterErrorCodeEnum::FailedWhenFlushingBuffer as ErrorCode,
        "刷新缓冲区时失败",
    );

    // 13301
    pub const CURRENT_INDEX_NOT_AT_THE_END_OF_BUFFER_WHEN_FLUSHING: &'static CiftlError =
        &CiftlError::new(
            CrypterErrorCodeEnum::CurrentIndexNotAtTheEndOfBufferWhenFlushing as ErrorCode,
            "刷新时当前下标不在缓冲区的最后",
        );

    // 13401
    pub const FAILED_WHEN_CHECKING_CRC32_VALUE_OF_DECRYPTED_CONTENT: &'static CiftlError =
        &CiftlError::new(
            CrypterErrorCodeEnum::FailedWhenCheckingCrc32ValueOfDecryptedContent as ErrorCode,
            "解密后内容无法通过校验",
        );

    // 13403
    pub const FAILED_WHEN_DECODING_STRING: &'static CiftlError = &CiftlError::new(
        CrypterErrorCodeEnum::FailedWhenDecodingString as ErrorCode,
        "字符串解码时失败",
    );

    // 13404
    pub const CANNOT_ENCRYPT_EMPTY_STRING: &'static CiftlError = &CiftlError::new(
        CrypterErrorCodeEnum::CannotEncryptEmptyString as ErrorCode,
        "不能对空串加密",
    );
}
