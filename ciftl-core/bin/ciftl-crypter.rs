#[macro_use]
extern crate prettytable;

use std::default;
use std::fs::read_to_string;
use std::io;
use std::io::Read;

use clap::Parser;

use prettytable::{Cell, Row, Table};

use ciftl_core::crypter::chacha20::ChaCha20CipherAlgorithm;
use ciftl_core::crypter::StringCrypter;
use ciftl_core::crypter::StringCrypterTrait;
use ciftl_core::crypter::StringCrypterTrait as _;
use ciftl_core::*;

enum CrypterModeEnum {
    Encrypt,
    Decrypt,
}
enum FormatModeEnum {
    None,
    Table,
    CSV,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Cipher Algorithm
    #[arg(short='a', long="algorithm", default_value_t = String::from("ChaCha20"))]
    pub algorithm: String,

    /// Encrypt or Decrypt
    #[arg(short = 'm', long = "mode", default_value_t = String::from("encrypt"))]
    pub cryption_mode: String,

    /// Password
    #[arg(short = 'p', long = "password")]
    pub password: String,

    /// Format
    #[arg(short = 'f', long = "format", default_value_t= String::from("none"))]
    pub format: String,
}

fn main() {
    let args = Args::parse();
    let algorithm = &args.algorithm[..];
    let password = &args.password[..];
    let mode = match &args.cryption_mode as &str {
        "encrypt" => CrypterModeEnum::Encrypt,
        "decrypt" => CrypterModeEnum::Decrypt,
        _ => panic!("Invalid cryption mode!"),
    };
    let format = match &args.format as &str {
        "none" => FormatModeEnum::None,
        "table" => FormatModeEnum::Table,
        "csv" => FormatModeEnum::CSV,
        _ => panic!("Invalid format mode!"),
    };
    // 目前只支持ChaCha20
    let str_crypter: Box<dyn StringCrypterTrait> = match algorithm {
        "ChaCha20" => Box::new(StringCrypter::<ChaCha20CipherAlgorithm>::default()),
        _ => panic!("Invalid cipher algorithm!"),
    };
    // 获取输入内容
    let mut content = String::new();
    let _ = io::stdin().read_to_string(&mut content).unwrap();
    // 按行切分
    let res = content.trim().split("\n");
    let do_cryption = |s: &str| -> Result<String> {
        Ok(match mode {
            CrypterModeEnum::Encrypt => str_crypter.encrypt(s, password)?,
            CrypterModeEnum::Decrypt => str_crypter.decrypt(s, password)?,
        })
    };
    // 处理
    let mut results = Vec::<(&str, Result<String>)>::new();
    for item in res {
        let item = item.trim();
        let res = do_cryption(item);
        results.push((item, res));
    }
    match format {
        FormatModeEnum::None => {
            for item in results {
                let (_, out) = item;
                match out {
                    Ok(s) => println!("{}", s),
                    Err(e) => println!("{}", e),
                }
            }
        }
        FormatModeEnum::Table => {
            // 制表
            let mut table = Table::new();
            // 添加行
            table.add_row(row!["Input", "Output", "Message"]);

            for item in results {
                let (instr, out) = item;
                match out {
                    Ok(s) => {
                        table.add_row(Row::new(vec![
                            Cell::new(instr),
                            Cell::new(&s),
                            Cell::new("OK"),
                        ]));
                    }
                    Err(e) => {
                        table.add_row(Row::new(vec![
                            Cell::new(instr),
                            Cell::new(""),
                            Cell::new(&format!("{e}")),
                        ]));
                    }
                }
            }
            // 打印表格到标准输出
            table.printstd();
        }
        FormatModeEnum::CSV => {
            println!("Input,Output,Message");
            for item in results {
                let (instr, out) = item;
                match out {
                    Ok(s) => {
                        println!("{},{},{}", instr, s, "OK");
                    }
                    Err(e) => {
                        println!("{},{},{}", instr, "", e)
                    }
                }
            }
        }
    }
}
