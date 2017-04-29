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
    pub fn map<F: Fn(&mut Matrix, u32) + Sync>(&mut self,
                                               blocks: &mut Matrix, f: &F) {
        match self {
            &mut Workers(1, _) => f(blocks, 0),
            &mut Workers(lanes, Some(ref mut pool)) => {
                pool.scoped(|sc| {
                    for lane in 0..lanes {
                        let m = unsafe { blocks.mut_ref() };
                        sc.execute(move || f(m, lane));
                    }
                })
            }
            _ => unreachable!(),
        }
    }
}
