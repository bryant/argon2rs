// benches argon2rs against the reference c implementation at
// https://github.com/p-h-c/phc-winner-argon2

#![feature(test)]

extern crate test;
extern crate argon2rs;
extern crate cargon;

use argon2rs::{Argon2, defaults};
use argon2rs::Variant::Argon2i;
use std::ptr;

const PASSWORD: &'static [u8] = b"cargo bench --feature=simd";
const SALT: &'static [u8] = b"cargo test --release";

#[bench]
fn bench_argon2rs_i(b: &mut test::Bencher) {
    let a2 = Argon2::default(Argon2i);
    let mut out = [0; defaults::LENGTH];
    b.iter(|| a2.hash(&mut out, PASSWORD, SALT, &[], &[]));
}

#[bench]
fn bench_cargon_i(b: &mut test::Bencher) {
    let mut out = [0; defaults::LENGTH];
    let mut ctx = cargon::CargonContext {
        out: out.as_mut_ptr(),
        outlen: out.len() as u32,
        pwd: PASSWORD.as_ptr(),
        pwdlen: PASSWORD.len() as u32,
        salt: SALT.as_ptr(),
        saltlen: SALT.len() as u32,
        secret: ptr::null(),
        secretlen: 0,
        ad: ptr::null(),
        adlen: 0,

        t_cost: defaults::PASSES,
        m_cost: defaults::KIB,
        lanes: defaults::LANES,
        threads: defaults::LANES,
        version: 0x10,
        allocate_fptr: ptr::null(),
        deallocate_fptr: ptr::null(),
        flags: cargon::ARGON2_FLAG_CLEAR_MEMORY,
    };

    b.iter(|| unsafe { cargon::argon2_ctx(&mut ctx, Argon2i as usize) });
}
