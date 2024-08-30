//! Implementation of <https://tools.ietf.org/html/rfc6479> as required

const SIZE_OF_WORD: usize = core::mem::size_of::<usize>() * 8;
const REDUNDANT_BIT_SHIFTS: u32 = SIZE_OF_WORD.ilog2();

const BITMAP_BITLEN: usize = 2048;
const BITMAP_LEN: usize = BITMAP_BITLEN / SIZE_OF_WORD;
const BITMAP_INDEX_MASK: usize = BITMAP_LEN - 1;
const BITMAP_LOC_MASK: u64 = (SIZE_OF_WORD as u64) - 1;
const WINDOW_SIZE: u64 = (BITMAP_BITLEN - SIZE_OF_WORD) as u64;

#[derive(Default)]
pub struct AntiReplay {
    bitmap: [usize; BITMAP_LEN],
    last: u64,
}

impl AntiReplay {
    pub fn check(&mut self, n: u64) -> bool {
        let index = (n >> REDUNDANT_BIT_SHIFTS) as usize;
        let shift = n & BITMAP_LOC_MASK;

        if n > self.last {
            let next_index = ((self.last >> REDUNDANT_BIT_SHIFTS) + 1) as usize;

            // edge case - skips the entire window ahead.
            if index > next_index && index - next_index > BITMAP_LEN {
                self.bitmap = [0; BITMAP_LEN];
            } else {
                for i in next_index..=index {
                    self.bitmap[i & BITMAP_INDEX_MASK] = 0;
                }
            };

            self.bitmap[index & BITMAP_INDEX_MASK] |= 1 << shift;
            self.last = n;

            return true;
        }

        let d = self.last - n;
        if d >= WINDOW_SIZE {
            return false;
        }

        let seen = (self.bitmap[index & BITMAP_INDEX_MASK] >> shift) & 1;
        self.bitmap[index & BITMAP_INDEX_MASK] |= 1 << shift;

        seen == 0
    }
}

#[cfg(test)]
mod tests {
    use super::AntiReplay;

    #[test]
    fn check() {
        let mut replay = AntiReplay::default();
        for i in 0..2048 {
            assert!(replay.check(i * 2 + 1));
            assert!(!replay.check(i * 2 + 1));
            assert!(replay.check(i * 2));
            assert!(!replay.check(i * 2));
        }
        for i in 0..4096 {
            assert!(!replay.check(i));
        }
        assert!(replay.check(4096 + 2048));
        assert!(!replay.check(4097));

        assert!(replay.check(65535));
        assert!(!replay.check(10000));

        assert!(replay.check(66000));

        // assert!(replay.check(8192));
        // assert!(!replay.check(4096));
    }
}
