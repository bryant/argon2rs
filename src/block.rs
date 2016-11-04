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

pub struct Matrix(Vec<Vec<Block>>);

impl Index<(u32, u32)> for Matrix {
    type Output = Block;

    #[inline(always)]
    fn index(&self, idx: (u32, u32)) -> &Block {
        match idx {
            (row, col) => unsafe {
                self.0.get_unchecked(row as usize).get_unchecked(col as usize)
            },
        }
    }
}

impl IndexMut<(u32, u32)> for Matrix {
    #[inline(always)]
    fn index_mut(&mut self, idx: (u32, u32)) -> &mut Block {
        match idx {
            (row, col) => unsafe {
                self.0
                    .get_unchecked_mut(row as usize)
                    .get_unchecked_mut(col as usize)
            },
        }
    }
}

impl Matrix {
    pub fn new(lanes: u32, lanelen: u32) -> Self {
        let newlane = || (0..lanelen).map(|_| zero()).collect();
        Matrix((0..lanes).map(|_| newlane()).collect())
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

    pub fn lanes_as_mut(&mut self) -> Vec<&mut Self> {
        let p: *mut Self = self;
        (0..self.0.len()).map(|_| unsafe { &mut (*p) }).collect()
    }

    pub fn col(&self, col: u32) -> Vec<&Block> {
        self.0.iter().map(|l| &l[col as usize]).collect()
    }

    pub fn iter(&self) -> Iter<Vec<Block>> { self.0.iter() }
}

impl Drop for Matrix {
    fn drop(&mut self) {
        for lane in self.0.iter_mut() {
            for blk in lane.iter_mut() {
                *blk = zero();
            }
        }
    }
}
