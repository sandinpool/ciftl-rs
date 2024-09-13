pub mod hex;
pub mod base64;

use crate::{etc::ByteVector, Result};

pub trait Encoding
{
    fn encode(&self, data : &[u8]) -> String;
    fn decode(&self, data : &str) -> Result<ByteVector>;
}

