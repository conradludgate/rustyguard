//! Implementation of <https://tools.ietf.org/html/rfc6479> as required

const SIZE_OF_WORD: usize = core::mem::size_of::<usize>() * 8;
const REDUNDANT_BIT_SHIFTS: u32 = SIZE_OF_WORD.ilog2();

const BITMAP_BITLEN: usize = 2048;
const BITMAP_LEN: usize = BITMAP_BITLEN / SIZE_OF_WORD;
const BITMAP_INDEX_MASK: usize = BITMAP_LEN - 1;
const BITMAP_LOC_MASK: u64 = (SIZE_OF_WORD as u64) - 1;
pub const WINDOW_SIZE: u64 = (BITMAP_BITLEN - SIZE_OF_WORD) as u64;

#[derive(Default)]
pub struct AntiReplay {
    bitmap: [usize; BITMAP_LEN],
    last: u64,
}

impl AntiReplay {
    /// Would the counter `n` be accepted right now? Read-only.
    ///
    /// Per RFC 6479 §3.4.3, callers MUST gate AEAD decryption on this and
    /// only call [`AntiReplay::mark_seen`] once the tag verifies, otherwise
    /// forged high-counter packets advance the window and lock out
    /// legitimate traffic.
    pub fn would_accept(&self, n: u64) -> bool {
        if n > self.last {
            return true;
        }

        let d = self.last - n;
        if d >= WINDOW_SIZE {
            return false;
        }

        let index = (n >> REDUNDANT_BIT_SHIFTS) as usize;
        let shift = n & BITMAP_LOC_MASK;
        let seen = (self.bitmap[index & BITMAP_INDEX_MASK] >> shift) & 1;
        seen == 0
    }

    /// Record an authenticated counter. Must only be called after
    /// [`AntiReplay::would_accept`] returned true for the same `n`.
    pub fn mark_seen(&mut self, n: u64) {
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

            self.last = n;
        }

        self.bitmap[index & BITMAP_INDEX_MASK] |= 1 << shift;
    }
}

#[cfg(test)]
mod tests {
    use super::AntiReplay;

    fn check(r: &mut AntiReplay, n: u64) -> bool {
        if !r.would_accept(n) {
            return false;
        }
        r.mark_seen(n);
        true
    }

    #[test]
    fn check_accept_and_mark() {
        let mut replay = AntiReplay::default();
        for i in 0..2048 {
            assert!(check(&mut replay, i * 2 + 1));
            assert!(!check(&mut replay, i * 2 + 1));
            assert!(check(&mut replay, i * 2));
            assert!(!check(&mut replay, i * 2));
        }
        for i in 0..4096 {
            assert!(!check(&mut replay, i));
        }
        assert!(check(&mut replay, 4096 + 2048));
        assert!(!check(&mut replay, 4097));

        assert!(check(&mut replay, 65535));
        assert!(!check(&mut replay, 10000));

        assert!(check(&mut replay, 66000));
    }

    /// Regression test for RFC 6479 §3.4.3: an observed-but-unauthenticated
    /// high counter must not advance the window.
    #[test]
    fn unauthenticated_high_counter_does_not_lock_out() {
        let mut replay = AntiReplay::default();
        assert!(check(&mut replay, 5));
        assert!(replay.would_accept(1_000_000));
        assert!(check(&mut replay, 6));
    }
}
