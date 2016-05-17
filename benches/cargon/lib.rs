#[repr(C)]
pub struct CargonContext {
    pub out: *mut u8, // output array
    pub outlen: u32, // digest length

    pub pwd: *const u8, // password array
    pub pwdlen: u32, // password length

    pub salt: *const u8, // salt array
    pub saltlen: u32, // salt length

    pub secret: *const u8, // key array
    pub secretlen: u32, // key length

    pub ad: *const u8, // associated data array
    pub adlen: u32, // associated data length

    pub t_cost: u32, // number of passes
    pub m_cost: u32, // amount of memory requested (KB)
    pub lanes: u32, // number of lanes
    pub threads: u32, // maximum number of threads

    pub version: u32, // version number

    pub allocate_fptr: *const u8, // pointer to memory allocator
    pub deallocate_fptr: *const u8, // pointer to memory deallocator

    pub flags: u32, // array of bool options
}

extern "C" {
    pub fn argon2_ctx(context: *mut CargonContext, ty: usize) -> usize;
}

pub const ARGON2_FLAG_CLEAR_MEMORY: u32 = 1 << 2;
