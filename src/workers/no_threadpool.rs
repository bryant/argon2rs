use block::Matrix;

pub struct Workers();

impl Workers {
    #[inline(always)]
    pub fn new(lanes: u32) -> Workers {
        match lanes {
            1 => Workers(),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub fn map<F: Fn(&mut Matrix, u32) + Sync>(&mut self,
                                               blocks: &mut Matrix, f: &F) {
        f(blocks, 0);
    }
}
