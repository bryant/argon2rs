#[cfg(feature = "threaded")]
pub use self::threadpool::Workers;

#[cfg(feature = "threaded")]
mod threadpool {
    extern crate scoped_threadpool;
    use block::Matrix;

    pub struct Workers(u32, Option<scoped_threadpool::Pool>);

    impl Workers {
        #[inline(always)]
        pub fn new(lanes: u32) -> Workers {
            match lanes {
                1 => Workers(lanes, None),
                n => Workers(lanes, Some(scoped_threadpool::Pool::new(n))),
            }
        }

        #[inline(always)]
        pub fn map<F>(&mut self, blocks: &mut Matrix, fill_slice: &F)
            where F: Fn(&mut Matrix, u32) + Sync
        {
            match self {
                &mut Workers(1, _) => fill_slice(blocks, 0),
                &mut Workers(lanes, Some(ref mut pool)) => {
                    pool.scoped(|sc| {
                        for lane in 0..lanes {
                            let m = unsafe { blocks.mut_ref() };
                            sc.execute(move || fill_slice(m, lane));
                        }
                    })
                }
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(not(feature = "threaded"))]
pub use self::threaded::Workers;

#[cfg(not(feature = "threaded"))]
mod threaded {
    use block::Matrix;

    /// Holds the number of lanes.
    pub struct Workers(u32);

    impl Workers {
        #[inline(always)]
        pub fn new(lanes: u32) -> Workers { Workers(lanes) }

        #[inline(always)]
        pub fn map<F>(&mut self, blocks: &mut Matrix, fill_slice: &F)
            where F: Fn(&mut Matrix, u32) + Sync
        {
            for lane in 0..self.0 {
                fill_slice(blocks, lane);
            }
        }
    }
}
