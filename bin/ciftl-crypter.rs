use std::default;
use std::error::Error;
use std::fmt::Display;
use std::fs::read_to_string;
use std::io;
use std::io::Read;
use std::io::Write;

#[macro_use]
extern crate prettytable;

extern crate serde;

#[macro_use]
use clap::{Parser, ValueEnum};

use prettytable::{Cell, Row, Table};

use ciftl::crypter::chacha20::ChaCha20CipherAlgorithm;
use ciftl::crypter::StringCrypter;
use ciftl::crypter::StringCrypterTrait;
use ciftl::crypter::StringCrypterTrait as _;
use ciftl::*;

/// 加密算法
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CipherAlgorithm {
    ChaCha20,
}

/// 加密/解密模式
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CryptionModeEnum {
    Encrypt,
    Decrypt,
}

/// 输出的格式
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum FormatModeEnum {
    None,
    Table,
    CSV,
}

/// 结果项
struct ResultItem(String, String, String);

/// 命令行相关参数
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliCommand {
    /// Cipher Algorithm
    #[arg(short = 'a', long = "algorithm", value_enum, default_value_t = CipherAlgorithm::ChaCha20)]
    pub algorithm: CipherAlgorithm,

    /// Encrypt or Decrypt
    #[arg(short = 'm', long = "mode", value_enum, default_value_t = CryptionModeEnum::Encrypt)]
    pub cryption_mode: CryptionModeEnum,

    /// Password
    #[arg(short = 'p', long = "password")]
    pub password: String,

    /// Format
    #[arg(short = 'f', long = "format", value_enum, default_value_t = FormatModeEnum::Table)]
    pub format: FormatModeEnum,
}

/// 制表
pub fn make_table(v: &Vec<ResultItem>) -> Table {
    // 制表
    let mut table = Table::new();
    // 添加行
    table.add_row(row!["Input", "Output", "Message"]);

    for item in v {
        table.add_row(Row::new(vec![
            Cell::new(&item.0),
            Cell::new(&item.1),
            Cell::new(&item.2),
        ]));
    }
    table
}

fn main() {
    // 获取所有的命令行参数
    let args = CliCommand::parse();
    let algorithm = &args.algorithm;
    let password = &args.password[..];
    let mode = &args.cryption_mode;
    let format = &args.format;
    // 获取输入并处理得到结果
    let results: Vec<ResultItem> = {
        // 创建加密器，目前只支持ChaCha20
        let str_crypter: Box<dyn StringCrypterTrait> = match algorithm {
            CipherAlgorithm::ChaCha20 => {
                Box::new(StringCrypter::<ChaCha20CipherAlgorithm>::default())
            }
        };
        let mut content = String::new();
        let _ = io::stdin().read_to_string(&mut content).unwrap();
        // 按行切分
        let res = content.trim().split("\n");
        // 进行加密/解密操作
        let do_cryption = |s: &str| -> Result<String> {
            Ok(match mode {
                CryptionModeEnum::Encrypt => str_crypter.encrypt(s, password)?,
                CryptionModeEnum::Decrypt => str_crypter.decrypt(s, password)?,
            })
        };
        let mut results = Vec::<ResultItem>::new();
        // 执行处理
        for item in res {
            let item = item;
            match do_cryption(item) {
                Ok(v) => results.push(ResultItem(item.to_string(), v, "Ok".to_string())),
                Err(e) => {
                    results.push(ResultItem(item.to_string(), "".to_string(), format!("{e}")))
                }
            }
        }
        results
    };
    // 输出结果
    match format {
        FormatModeEnum::None => {
            for item in results {
                let ResultItem(_, out, _) = item;
                // 这里out有可能会是空行
                println!("{}", out);
            }
        }
        FormatModeEnum::Table => {
            let t = make_table(&results);
            let _ = t.printstd();
        }
        FormatModeEnum::CSV => {
            let t = make_table(&results);
            let _ = t.to_csv(std::io::stdout());
        }
    }
}
