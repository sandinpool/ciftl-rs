use std::fmt;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[derive(FromPrimitive)]
enum ErrorCodeEnum {
    EncodingError = 10000,
    // Hex的错误段
    HexEncodingError = 11000,
    // Bin的错误段
    BinEncodingError = 12000,
    // Base64的错误段
    Base64EncodingError = 13000,
    Base64BadDecodingSource = 13001,
    // 加密器错误段
    CrypterError = 20000
}

pub type ErrorCode = u32;

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
                "Code: {}, Error Message: {}, Optional Message: {}",
                self.m_error_code, self.m_error_message, m
            )
        } else {
            write!(
                f,
                "Code: {}, Error Message: {}",
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

pub type CiftlResult<T> = Result<T, CiftlError>;

pub const BASE64_BAD_DECODING_SOURCE: &'static CiftlError = &CiftlError::new(
    ErrorCodeEnum::Base64BadDecodingSource as ErrorCode,
    "非法的Base64字符串",
);
