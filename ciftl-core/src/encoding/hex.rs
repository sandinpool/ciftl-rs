use crate::encoding::Encoding;
use crate::etc::error::HEX_BAD_DECODING_SOURCE;
use crate::*;

pub enum HexEncodingCase {
    UpperCase,
    LowerCase,
}

pub struct HexEncoding(HexEncodingCase);

impl HexEncoding {
    pub const fn new(case: HexEncodingCase) -> HexEncoding {
        HexEncoding(case)
    }
}

impl Default for HexEncoding {
    fn default() -> Self {
        HexEncoding(HexEncodingCase::UpperCase)
    }
}

impl Encoding for HexEncoding {
    fn encode(&self, data: &[u8]) -> String {
        let res = hex::encode(data);
        if let HexEncodingCase::LowerCase = self.0 {
            return res.as_str().to_lowercase();
        }
        res.as_str().to_uppercase()
    }
    fn decode(&self, data: &str) -> Result<ByteVector> {
        let res = hex::decode(data);
        if let Ok(v) = res {
            return Ok(v);
        }
        let error_message = format!("{}", res.unwrap_err());
        Err(HEX_BAD_DECODING_SOURCE.add_opt_mess(&error_message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let hexe = HexEncoding::default();
        let res = hexe.encode("\\]^_`abcde".as_bytes());
        assert_eq!("5C5D5E5F606162636465".to_string(), res);
        let res = hexe.decode(&res).unwrap();
        assert_eq!("\\]^_`abcde".as_bytes(), &res[..]);
        let res = hexe.decode("5C5D5E5F6061626364651");
        assert!(res.is_err());
        println!("错误：{}", res.unwrap_err());
        let res = hexe.decode("5C5D5E5F60616263646%");
        assert!(res.is_err());
        println!("错误：{}", res.unwrap_err());
    }
}
