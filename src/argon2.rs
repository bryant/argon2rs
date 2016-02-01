extern crate blake2;

use std::mem;
use self::blake2::Blake2b;
use std::iter::FromIterator;
use std::ptr;

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum Argon2Variant {
    Argon2d = 0,
    Argon2i = 1,
}

const ARGON2_BLOCK_BYTES: usize = 1024;
const ARGON2_VERSION: u32 = 0x10;
const DEF_B2HASH_LEN: usize = 64;
const SLICES_PER_LANE: u32 = 4;
// from run.c
const T_COST_DEF: u32 = 3;
const LOG_M_COST_DEF: u32 = 12;
const LANES_DEF: u32 = 1;

macro_rules! per_block {
    (u8) => { ARGON2_BLOCK_BYTES };
    (u64) => { ARGON2_BLOCK_BYTES / 8 };
}

pub type Block = [u64; per_block!(u64)];

pub fn zero() -> Block { [0; per_block!(u64)] }

pub fn xor_all(blocks: &Vec<&Block>) -> Block {
    let mut rv: Block = zero();
    for (idx, d) in rv.iter_mut().enumerate() {
        *d = blocks.iter().fold(0, |n, &&blk| n ^ blk[idx]);
    }
    rv
}

pub fn as32le(k: u32) -> [u8; 4] { unsafe { mem::transmute(k.to_le()) } }

fn len32(t: &[u8]) -> [u8; 4] { as32le(t.len() as u32) }

fn as_u8_mut(b: &mut Block) -> &mut [u8] {
    let rv: &mut [u8; per_block!(u8)] = unsafe { mem::transmute(b) };
    rv
}

fn as_u8(b: &Block) -> &[u8] {
    let rv: &[u8; per_block!(u8)] = unsafe { mem::transmute(b) };
    rv
}

macro_rules! b2hash {
    ($($bytes: expr),*) => {
        {
            let mut out: [u8; DEF_B2HASH_LEN] = unsafe { mem::uninitialized() };
            b2hash!(&mut out; $($bytes),*);
            out
        }
    };
    ($out: expr; $($bytes: expr),*) => {
        {
            let mut b = Blake2b::new($out.len());
            $(b.update($bytes));*;
            b.finalize($out);
        }
    };
}

fn u8_string(bs: &[u8]) -> String {
    let mut rv = String::new();
    for b in bs.iter() {
        rv.push_str(&format!("{:02x} ", b));
    }
    rv
}

fn blksum(blk: &Block) -> u64 { blk.iter().fold(0 as u64, |sum, &n| n + sum) }

#[cfg_attr(rustfmt, rustfmt_skip)]
pub fn h0(lanes: u32, hash_length: u32, memory_kib: u32, passes: u32,
          version: u32, variant: Argon2Variant,
          p: &[u8], s: &[u8], k: &[u8], x: &[u8])
          -> [u8; 72] {
    let mut rv = [0 as u8; 72];
    b2hash!(&mut rv[0..DEF_B2HASH_LEN];
            &as32le(lanes), &as32le(hash_length), &as32le(memory_kib),
            &as32le(passes), &as32le(version), &as32le(variant as u32),
            &len32(p), p,
            &len32(s), s,
            &len32(k), k,
            &len32(x), x);
    rv
}

pub struct Argon2 {
    pub blocks: Vec<Block>,
    passes: u32,
    lanelen: u32,
    lanes: u32,
    origkib: u32,
    variant: Argon2Variant,
}

impl Argon2 {
    pub fn new(passes: u32, lanes: u32, memory_kib: u32, variant: Argon2Variant)
               -> Argon2 {
        assert!(lanes >= 1 && memory_kib >= 8 * lanes && passes >= 1);
        let lanelen = memory_kib / (4 * lanes) * 4;
        Argon2 {
            blocks: (0..lanelen * lanes).map(|_| zero()).collect(),
            passes: passes,
            lanelen: lanelen,
            lanes: lanes,
            origkib: memory_kib,
            variant: variant,
        }
    }

    pub fn simple(&mut self, out: &mut [u8], p: &[u8], s: &[u8]) {
        self.hash(out, p, s, &[], &[])
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn hash(&mut self, out: &mut [u8], p: &[u8], s: &[u8], k: &[u8],
                x: &[u8]) {
        let h0 = h0(self.lanes, out.len() as u32, self.origkib, self.passes,
                    ARGON2_VERSION, self.variant, p, s, k, x);
        println!("{:08x} lanes", self.lanes);
        println!("{:08x} hashlen", out.len() as u32);
        println!("{:08x} m", self.origkib);
        println!("{:08x} t", self.passes);
        println!("{:08x} |p|", p.len() as u32);
        println!("{}", u8_string(p));
        println!("{:08x} |s|", s.len() as u32);
        println!("{}", u8_string(s));
        println!("{:08x} |k|", k.len());
        println!("{}", u8_string(k));
        println!("{:08x} |x|", x.len());
        println!("{}", u8_string(x));
        println!("h0:");
        for ns in (&h0[0..DEF_B2HASH_LEN]).chunks(16) {
            println!("{}", u8_string(ns));
        }

        // TODO: parallelize
        for l in 0..self.lanes {
            let h0__ = h0;
            self.fill_first_slice(h0__, l);
        }

        // finish first pass. slices have to be filled in sync.
        for slice in 1..4 {
            for l in 0..self.lanes {
                self.fill_slice(0, l, slice);
            }
        }

        for p in 1..self.passes {
            for s in 0..SLICES_PER_LANE {
                for l in 0..self.lanes {
                    self.fill_slice(p, l, s);
                }
            }
        }

        let lastcol: Vec<&Block> = Vec::from_iter((0..self.lanes).map(|l| {
            &self.blocks[self.blkidx(l, self.lanelen - 1)]
        }));

        h_prime(out, as_u8(&xor_all(&lastcol)));
    }

    fn blkidx(&self, row: u32, col: u32) -> usize {
        (self.lanelen * row + col) as usize
    }

    pub fn fill_first_slice(&mut self, mut h0: [u8; 72], lane: u32) {
        // fill the first (of four) slice
        copy_memory(&as32le(lane), &mut h0[68..72]);

        copy_memory(&as32le(0), &mut h0[64..68]);
        let zeroth = self.blkidx(lane, 0);
        h_prime(as_u8_mut(&mut self.blocks[zeroth]), &h0);

        copy_memory(&as32le(1), &mut h0[64..68]);
        let first = self.blkidx(lane, 1);
        h_prime(as_u8_mut(&mut self.blocks[first]), &h0);

        // finish rest of first slice
        let (m_, slicelen) = (self.blocks.len() as u32, self.lanelen / 4);
        // TODO: argon2d
        for ((j1, j2), idx) in IndexGen::new(0, lane, 0, m_, self.passes)
                                   .skip(2)
                                   .zip(2..slicelen) {
            let z = index_alpha(0, lane, 0, self.lanes, idx, slicelen, j1, j2);
            let _k = self.blkidx(lane, z);
            // ^^^ r == s == 0 -> l = current lane

            let w = self.blkidx(lane, idx);
            let (wr, prev, refblk) = get3(&mut self.blocks, w, w - 1, _k);
            g(wr, prev, refblk);
        }
    }

    pub fn fill_slice(&mut self, pass: u32, lane: u32, slice: u32) {
        let slicelen = self.lanelen / SLICES_PER_LANE;
        let m_ = self.blocks.len() as u32;
        let p = self.passes;

        for ((j1, j2), idx) in IndexGen::new(pass, lane, slice, m_, p)
                                   .zip(0..slicelen) {
            let ls = self.lanes;
            let z = index_alpha(pass, lane, slice, ls, idx, slicelen, j1, j2);

            let _k = self.blkidx(j2 % self.lanes, z);
            let w = self.blkidx(lane, slice * slicelen + idx);
            let _p = if w % self.lanelen as usize != 0 { w - 1 } else { w + self.lanelen as usize - 1 };

            let (wr, prev, refblk) = get3(&mut self.blocks, w, _p, _k);
            g(wr, prev, refblk);
        }
    }
}

pub fn get3<T>(vector: &mut Vec<T>, wr: usize, rd0: usize, rd1: usize)
               -> (&mut T, &T, &T) {
    assert!(wr != rd0 && wr != rd1 && wr < vector.len() &&
            rd0 < vector.len() && rd1 < vector.len());
    let p: *mut [T] = &mut vector[..];
    let rv = unsafe { (&mut (*p)[wr], &(*p)[rd0], &(*p)[rd1]) };
    println!("{} {} {}", wr, rd0, rd1);
    rv
}

pub fn h_prime(out: &mut [u8], input: &[u8]) {
    if out.len() <= DEF_B2HASH_LEN {
        b2hash!(out; &len32(out), input);
    } else {
        let mut tmp = b2hash!(&len32(out), input);
        copy_memory(&tmp, &mut out[0..DEF_B2HASH_LEN]);
        let mut wr_at: usize = 32;

        while out.len() - wr_at > DEF_B2HASH_LEN {
            b2hash!(&mut tmp; &tmp);
            copy_memory(&tmp, &mut out[wr_at..wr_at + DEF_B2HASH_LEN]);
            wr_at += DEF_B2HASH_LEN / 2;
        }

        let len = out.len() - wr_at;
        b2hash!(&mut out[wr_at..wr_at + len]; &tmp);
    }
}

// from opt.c
pub fn index_alpha(pass: u32, lane: u32, slice: u32, lanes: u32, sliceidx: u32,
                   slicelen: u32, j1: u32, j2: u32)
                   -> u32 {
    let lanelen = slicelen * 4;
    let r: u32 = match (pass, slice, j2 % lanes == lane) {
        (0, 0, _) => sliceidx - 1,
        (0, _, false) => slice * slicelen - if sliceidx == 0 { 1 } else { 0 },
        (0, _, true) => slice * slicelen + sliceidx - 1,
        (_, _, false) => lanelen - slicelen - if sliceidx == 0 { 1 } else { 0 },
        (_, _, true) => lanelen - slicelen + sliceidx - 1,
    };

    let (r_, j1_) = (r as u64, j1 as u64);
    let relpos: u32 = (r_ - 1 - (r_ * (j1_ * j1_ >> 32) >> 32)) as u32;

    let startpos: u32 = match (pass, slice) {
        (0, _) | (_, 3) => 0,
        _ => slicelen * (slice + 1),
    };

    println!("index_alpha {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} = {:08x}",
             pass, lane, slice, lanes, sliceidx, slicelen, j1, j2,
             (startpos + relpos) % lanelen);

    (startpos + relpos) % lanelen
}

pub struct IndexGen {
    arg: Block,
    pseudos: Block,
    idx: usize,
}

impl IndexGen {
    pub fn new(pass: u32, lane: u32, slice: u32, totblocks: u32, totpasses: u32)
               -> IndexGen {
        let args = [pass as u64,
                    lane as u64,
                    slice as u64,
                    totblocks as u64,
                    totpasses as u64,
                    Argon2Variant::Argon2i as u64];
        let mut rv = IndexGen {
            arg: zero(),
            pseudos: zero(),
            idx: 0,
        };

        for (k, v) in rv.arg.iter_mut().zip(args.into_iter()) {
            *k = *v;
        }
        rv.more();
        rv
    }

    pub fn more(&mut self) {
        self.arg[6] += 1;
        g_two(&mut self.pseudos, &self.arg);
    }
}

impl Iterator for IndexGen {
    type Item = (u32, u32);
    fn next(&mut self) -> Option<Self::Item> {
        let oct = self.pseudos[self.idx];
        self.idx = (self.idx + 1) % per_block!(u64);
        if self.idx == 0 {
            self.more();
        }
        Some(((oct & 0xffffffff) as u32, (oct >> 32) as u32))
    }
}

// g x y = let r = x `xor` y in p_col (p_row r) `xor` r,
// very simd-able.
pub fn g(dest: &mut Block, lhs: &Block, rhs: &Block) {
    for (d, (l, r)) in dest.iter_mut().zip(lhs.iter().zip(rhs.iter())) {
        *d = *l ^ *r;
    }

    for row in 0..8 {
        p_row(row, dest);
    }
    // column-wise, 2x u64 groups
    for col in 0..8 {
        p_col(col, dest);
    }

    for (d, (l, r)) in dest.iter_mut().zip(lhs.iter().zip(rhs.iter())) {
        *d = *d ^ *l ^ *r;
    }

    println!("rd0 {:016x}", blksum(lhs));
    println!("ref {:016x}", blksum(rhs));
    println!("blksum {:016x}", blksum(dest));

}

// g2 y = g 0 (g 0 y). used for data-independent index generation.
pub fn g_two(dest: &mut Block, src: &Block) {
    *dest = *src;

    for row in 0..8 {
        p_row(row, dest);
    }
    for col in 0..8 {
        p_col(col, dest);
    }

    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d = *d ^ *s;
    }

    let tmp: Block = *dest;

    for row in 0..8 {
        p_row(row, dest);
    }
    for col in 0..8 {
        p_col(col, dest);
    }

    for (d, s) in dest.iter_mut().zip(tmp.iter()) {
        *d = *d ^ *s;
    }
}

macro_rules! p {
    ($v0: expr, $v1: expr, $v2: expr, $v3: expr,
     $v4: expr, $v5: expr, $v6: expr, $v7: expr,
     $v8: expr, $v9: expr, $v10: expr, $v11: expr,
     $v12: expr, $v13: expr, $v14: expr, $v15: expr) => {
        g_blake2b!($v0, $v4, $v8, $v12); g_blake2b!($v1, $v5, $v9, $v13);
        g_blake2b!($v2, $v6, $v10, $v14); g_blake2b!($v3, $v7, $v11, $v15);
        g_blake2b!($v0, $v5, $v10, $v15); g_blake2b!($v1, $v6, $v11, $v12);
        g_blake2b!($v2, $v7, $v8, $v13); g_blake2b!($v3, $v4, $v9, $v14);
    };
}

macro_rules! g_blake2b {
    ($a: expr, $b: expr, $c: expr, $d: expr) => {
        $a = $a.wrapping_add($b).wrapping_add(lower_mult($a, $b));
        $d = ($d ^ $a).rotate_right(32);
        $c = $c.wrapping_add($d).wrapping_add(lower_mult($c, $d));
        $b = ($b ^ $c).rotate_right(24);
        $a = $a.wrapping_add($b).wrapping_add(lower_mult($a, $b));
        $d = ($d ^ $a).rotate_right(16);
        $c = $c.wrapping_add($d).wrapping_add(lower_mult($c, $d));
        $b = ($b ^ $c).rotate_right(63);

    }
}

fn p_row(row: usize, b: &mut Block) {
    p!(b[16 * row + 0],
       b[16 * row + 1],
       b[16 * row + 2],
       b[16 * row + 3],
       b[16 * row + 4],
       b[16 * row + 5],
       b[16 * row + 6],
       b[16 * row + 7],
       b[16 * row + 8],
       b[16 * row + 9],
       b[16 * row + 10],
       b[16 * row + 11],
       b[16 * row + 12],
       b[16 * row + 13],
       b[16 * row + 14],
       b[16 * row + 15]);
}

fn p_col(col: usize, b: &mut Block) {
    p!(b[2 * col + 16 * 0],
       b[2 * col + 16 * 0 + 1],
       b[2 * col + 16 * 1],
       b[2 * col + 16 * 1 + 1],
       b[2 * col + 16 * 2],
       b[2 * col + 16 * 2 + 1],
       b[2 * col + 16 * 3],
       b[2 * col + 16 * 3 + 1],
       b[2 * col + 16 * 4],
       b[2 * col + 16 * 4 + 1],
       b[2 * col + 16 * 5],
       b[2 * col + 16 * 5 + 1],
       b[2 * col + 16 * 6],
       b[2 * col + 16 * 6 + 1],
       b[2 * col + 16 * 7],
       b[2 * col + 16 * 7 + 1]);
}

fn lower_mult(a: u64, b: u64) -> u64 {
    fn lower32(k: u64) -> u64 { k & 0xffffffff }
    lower32(a).wrapping_mul(lower32(b)).wrapping_mul(2)
}

// TODO: from cryptoutil
#[inline]
pub fn copy_memory(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len());
    unsafe {
        let srcp = src.as_ptr();
        let dstp = dst.as_mut_ptr();
        ptr::copy_nonoverlapping(srcp, dstp, src.len());
    }
}
