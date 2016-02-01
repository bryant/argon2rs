extern crate argon2rs;

use argon2rs::{Argon2, Variant};
use std::string::String;
use std::env;

const CLI_TOOL_SALT_LEN: usize = 16;
const CLI_TOOL_HASH_LEN: usize = 32;

fn that_cli_tool(msg: &[u8], salt: &[u8], passes: u32, lanes: u32, logkib: u32)
                 -> [u8; CLI_TOOL_HASH_LEN] {
    assert!(salt.len() <= CLI_TOOL_SALT_LEN && passes > 0 && logkib > 0 &&
            lanes > 0);
    let mut a = Argon2::new(passes, lanes, 1 << logkib, Variant::Argon2i);
    let mut s = [0; CLI_TOOL_SALT_LEN];
    for (&v, mut k) in salt.iter().zip(s.iter_mut()) {
        *k = v;
    }

    let mut out = [0 as u8; CLI_TOOL_HASH_LEN];
    a.simple(&mut out, msg, &s);
    out
}

fn to_string(bs: &[u8]) -> String {
    let mut rv = String::new();
    for b in bs.iter() {
        rv.push_str(&format!("{:02x}", b));
    }
    rv
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 6 {
        println!("usage: {} passes lanes logkib msg salt", args[0]);
        return;
    }

    let t: u32 = args[1].parse().unwrap();
    let l: u32 = args[2].parse().unwrap();
    let logm: u32 = args[3].parse().unwrap();
    let msg = args[4].as_ref();
    let salt = args[5].as_ref();

    println!("Hash: {}", to_string(&that_cli_tool(msg, salt, t, l, logm)));
}
