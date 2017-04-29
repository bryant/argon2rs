use octword::u64x2;
use std::mem;
use std::ops::{BitXorAssign, Index, IndexMut};
use std::slice::{Iter, IterMut};

pub const ARGON2_BLOCK_BYTES: usize = 1024;

macro_rules! per_kib {
    (u8) => { ARGON2_BLOCK_BYTES };
    (u64) => { ARGON2_BLOCK_BYTES / 8 };
    (u64x2) => { ARGON2_BLOCK_BYTES / 16 };
}

pub struct Block([u64x2; per_kib!(u64x2)]);

impl Clone for Block {
    #[inline(always)]
    fn clone(&self) -> Self {
        let inner = self.0;
        Block(inner)
    }
}

impl Block {
    pub fn iter_mut(&mut self) -> IterMut<u64x2> { self.0.iter_mut() }

    pub fn iter(&self) -> Iter<u64x2> { self.0.iter() }

    pub fn as_u8_mut(&mut self) -> &mut [u8] {
        let rv: &mut [u8; per_kib!(u8)] =
            unsafe { mem::transmute(&mut self.0) };
        rv
    }

    pub fn as_u8(&self) -> &[u8] {
        let rv: &[u8; per_kib!(u8)] = unsafe { mem::transmute(&self.0) };
        rv
    }

    pub fn as_u64(&self) -> &[u64] {
        let rv: &[u64; per_kib!(u64)] = unsafe { mem::transmute(&self.0) };
        rv
    }
}

impl<'a> BitXorAssign<&'a Block> for Block {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: &Block) {
        for (d, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *d = *d ^ *r;
        }
    }
}

impl<'a, 'b> BitXorAssign<(&'a Block, &'b Block)> for Block {
    #[inline(always)]
    fn bitxor_assign(&mut self, (a, b): (&Block, &Block)) {
        for (d, (l, r)) in self.0.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            *d = *d ^ *l ^ *r;
        }
    }
}

impl Index<usize> for Block {
    type Output = u64x2;
    #[inline(always)]
    fn index(&self, idx: usize) -> &Self::Output {
        unsafe { self.0.get_unchecked(idx) }
    }
}

impl IndexMut<usize> for Block {
    #[inline(always)]
    fn index_mut(&mut self, idx: usize) -> &mut u64x2 {
        unsafe { self.0.get_unchecked_mut(idx) }
    }
}

pub fn zero() -> Block { Block([u64x2(0, 0); per_kib!(u64x2)]) }

pub struct Matrix {
    blocks: Vec<Block>,
    lanes: u32,
    lanelen: u32,
}

impl Index<(u32, u32)> for Matrix {
    type Output = Block;

    #[inline(always)]
    fn index(&self, idx: (u32, u32)) -> &Block {
        let (row, col) = idx;
        debug_assert!(row < self.lanes && col < self.lanelen);
        unsafe {
            self.blocks.get_unchecked(row as usize * self.lanelen as usize +
                                      col as usize)
        }
    }
}

impl IndexMut<(u32, u32)> for Matrix {
    #[inline(always)]
    fn index_mut(&mut self, idx: (u32, u32)) -> &mut Block {
        let (row, col) = idx;
        debug_assert!(row < self.lanes && col < self.lanelen);
        unsafe {
            self.blocks.get_unchecked_mut(row as usize * self.lanelen as usize +
                                          col as usize)
        }
    }
}

impl Matrix {
    pub fn new(lanes: u32, lanelen: u32) -> Self {
        debug_assert!(lanes > 0 && lanelen > 0);
        Matrix {
            blocks: vec![zero(); lanelen as usize * lanes as usize],
            lanes: lanes,
            lanelen: lanelen,
        }
    }

    pub fn get3(&mut self, wr: (u32, u32), rd0: (u32, u32), rd1: (u32, u32))
                -> (&mut Block, &Block, &Block) {
        assert!(wr != rd0 && wr != rd1);
        let p: *mut Matrix = self;
        unsafe { (&mut (*p)[wr], &(*p)[rd0], &(*p)[rd1]) }
    }

    pub unsafe fn mut_ref<'a>(&mut self) -> &'a mut Self {
        &mut *(self as *mut Self)
    }

    // Xors the Blocks of column `col` together.
    pub fn xor_column(&self, col: u32) -> Block {
        debug_assert!(col < self.lanelen);
        let mut rv = self[(0, col)].clone();
        for row in 1..self.lanes {
            rv ^= &self[(row, col)];
        }
        rv
    }

    pub fn iter(&self) -> Iter<Block> { self.blocks.iter() }
}

impl Drop for Matrix {
    fn drop(&mut self) {
        for blk in self.blocks.iter_mut() {
            *blk = zero();
        }
    }
}
