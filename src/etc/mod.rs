pub mod memory;
pub mod error;

// 重导出所有组件
pub use memory::{memcpy, xor, ByteArray, ByteVector, MemoryTaker};
pub use error::predef::*;
pub use error::{CiftlError, CiftlResult as Result, ErrorCode, ErrorCodeEnum};

