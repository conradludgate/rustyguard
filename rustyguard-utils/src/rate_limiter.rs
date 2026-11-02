use core::hash::{BuildHasher, Hash};

use foldhash::quality::FixedState;
use libm::{ceil, log};
use rand_core::CryptoRng;

extern crate alloc;
use alloc::vec::Vec;

/// Accuracy parameters for the per-IP handshake count-min sketch.
///
/// These control counter overestimation and memory usage, not the packet-count
/// threshold or reset interval. Larger epsilon and delta use less memory but
/// increase false positives. Parameters are checked when constructing the sketch.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitParams {
    /// Failure probability; must be strictly between zero and one.
    pub delta: f64,
    /// Additive error relative to the total number of packets counted. Must be
    /// finite and positive. The storage dimensions must also be representable.
    pub epsilon: f64,
}
impl RateLimitParams {
    /// The original handshake counter's accuracy and memory usage.
    pub const DEFAULT: Self = Self {
        delta: 0.01,
        epsilon: 10.0 / 20_000.0,
    };
    /// A smaller sketch with a looser overestimation bound.
    pub const LOW_MEMORY: Self = Self {
        delta: 0.05,
        epsilon: 100.0 / 20_000.0,
    };
}
impl Default for RateLimitParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// CountMinSketch is a fast, O(1) memory way to measure number of times we see a client
/// over time.
///
/// <https://en.wikipedia.org/wiki/Count%E2%80%93min_sketch>
pub struct CountMinSketch {
    // one for each depth
    hashers: Vec<FixedState>,
    width: usize,
    depth: usize,
    // buckets, width*depth
    buckets: Vec<u32>,
}

impl CountMinSketch {
    /// Given parameters (ε, δ),
    ///   set width = ceil(e/ε)
    ///   set depth = ceil(ln(1/δ))
    ///
    /// guarantees:
    /// actual <= estimate
    /// estimate <= actual + ε * N with probability 1 - δ
    /// where N is the total number of items counted, including repetitions.
    ///
    /// example:
    /// For 20,000 packets counted since reset, allow up to 100 excess counts
    /// with probability at least 95%:
    ///
    /// ```
    /// let δ = 0.05;
    /// let ε = 100.0 / 20_000.0;
    /// ```
    ///
    /// These parameters use 544 * 3 u32 buckets, plus the row hashers.
    ///
    /// example:
    /// For 20,000 packets counted since reset, allow up to 10 excess counts
    /// with probability at least 99%:
    ///
    /// ```
    /// let δ = 0.01;
    /// let ε = 10.0 / 20_000.0;
    /// ```
    ///
    /// These parameters use 5,437 * 5 u32 buckets, plus the row hashers.
    ///
    /// # Panics
    ///
    /// Panics if epsilon is not finite and positive, delta is not strictly
    /// between zero and one, or either storage layout is too large to represent.
    pub fn with_params(epsilon: f64, delta: f64, rng: &mut dyn CryptoRng) -> Self {
        assert!(
            epsilon.is_finite() && epsilon > 0.0,
            "epsilon must be finite and positive"
        );
        assert!(
            delta > 0.0 && delta < 1.0,
            "delta must be between zero and one"
        );
        CountMinSketch::new(
            ceil(core::f64::consts::E / epsilon) as usize,
            ceil(-log(delta)) as usize,
            rng,
        )
    }

    fn new(width: usize, depth: usize, rng: &mut dyn CryptoRng) -> Self {
        let len = width
            .checked_mul(depth)
            .expect("sketch dimensions overflow");
        core::alloc::Layout::array::<u32>(len).expect("sketch bucket storage is too large");
        core::alloc::Layout::array::<FixedState>(depth)
            .expect("sketch hasher storage is too large");
        Self {
            hashers: (0..depth)
                .map(|_| FixedState::with_seed(rng.next_u64()))
                .collect(),
            width,
            depth,
            buckets: alloc::vec![0; len],
        }
    }

    /// Count the packet, return the number of packets seen.
    pub fn count<T: Hash>(&mut self, t: &T) -> u32 {
        let mut min = u32::MAX;
        for row in 0..self.depth {
            let col = (self.hashers[row].hash_one(t) as usize) % self.width;

            let row = &mut self.buckets[row * self.width..][..self.width];
            row[col] = row[col].saturating_add(1);
            min = core::cmp::min(min, row[col]);
        }
        min
    }

    pub fn reset(&mut self, rng: &mut dyn CryptoRng) {
        self.buckets.fill(0);
        self.hashers
            .iter_mut()
            .for_each(|hasher| *hasher = FixedState::with_seed(rng.next_u64()));
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use rand::{rng, rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};

    extern crate alloc;
    extern crate std;

    use super::{CountMinSketch, RateLimitParams};

    #[test]
    fn low_memory_preset_uses_less_storage() {
        let default = RateLimitParams::default();
        let small = RateLimitParams::LOW_MEMORY;
        let default = CountMinSketch::with_params(default.epsilon, default.delta, &mut rng());
        let small = CountMinSketch::with_params(small.epsilon, small.delta, &mut rng());
        assert_eq!((default.width, default.depth), (5437, 5));
        assert_eq!((small.width, small.depth), (544, 3));
        assert!(small.buckets.len() < default.buckets.len());
    }

    #[test]
    fn invalid_parameters_are_rejected_before_using_rng() {
        for (epsilon, delta) in [
            (0.0, 0.01),
            (-1.0, 0.01),
            (f64::NAN, 0.01),
            (f64::INFINITY, 0.01),
            (1.0, 0.0),
            (1.0, 1.0),
            (1.0, -1.0),
            (1.0, f64::NAN),
            (1.0, f64::INFINITY),
            (f64::MIN_POSITIVE, 0.01),
        ] {
            let mut rng = StdRng::seed_from_u64(123);
            let expected = rng.clone().random::<u64>();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                CountMinSketch::with_params(epsilon, delta, &mut rng)
            }));
            assert!(result.is_err(), "accepted epsilon={epsilon}, delta={delta}");
            assert_eq!(rng.random::<u64>(), expected);
        }
    }

    #[test]
    fn small_failure_probability_does_not_overflow_its_reciprocal() {
        let mut sketch = CountMinSketch::with_params(1.0, f64::from_bits(1), &mut rng());
        assert_eq!((sketch.width, sketch.depth), (3, 745));
        assert_eq!(sketch.count(&42), 1);
    }

    fn eval_precision(n: usize, p: f64, q: f64) -> usize {
        // fixed value of phi for consistent test
        let mut rng = StdRng::seed_from_u64(16180339887498948482);

        #[allow(non_snake_case)]
        let mut N = 0;

        let mut ips = alloc::vec![];

        for _ in 0..n {
            // number of insert operations
            let n = rng.random_range(1..10);

            let ip = Ipv4Addr::from_bits(rng.random());
            ips.push((ip, n));

            // N = sum(actual)
            N += n;
        }

        // q% of counts will be within p of the actual value
        let mut sketch = CountMinSketch::with_params(p / N as f64, 1.0 - q, &mut rng);

        // insert a bunch of entries in a random order
        let mut ips2 = ips.clone();
        while !ips2.is_empty() {
            ips2.shuffle(&mut rng);

            let mut i = 0;
            while i < ips2.len() {
                sketch.count(&ips2[i].0);
                ips2[i].1 -= 1;
                if ips2[i].1 == 0 {
                    ips2.remove(i);
                } else {
                    i += 1;
                }
            }
        }

        let mut within_p = 0;
        for (ip, n) in ips {
            let estimate = sketch.count(&ip);
            let actual = n + 1;

            // This estimate has the guarantee that actual <= estimate
            assert!(actual <= estimate);

            // This estimate has the guarantee that estimate <= actual + εN with probability 1 - δ.
            // ε = p / N, δ = 1 - q;
            // therefore, estimate <= actual + p with probability q.
            if estimate as f64 <= actual as f64 + p {
                within_p += 1;
            }
        }
        within_p
    }

    #[test]
    fn precision() {
        assert_eq!(eval_precision(100, 100.0, 0.99), 100);
        assert_eq!(eval_precision(1000, 100.0, 0.99), 1000);
        assert_eq!(eval_precision(100, 4096.0, 0.99), 100);
        assert_eq!(eval_precision(1000, 4096.0, 0.99), 1000);

        // seems to be more precise than the literature indicates?
        // probably numbers are too small to truly represent the probabilities.
        assert_eq!(eval_precision(1000, 4096.0, 0.90), 1000);
        assert_eq!(eval_precision(10000, 4096.0, 0.90), 10000);
        assert_eq!(eval_precision(1000, 4096.0, 0.1), 1000);
        assert_eq!(eval_precision(10000, 4096.0, 0.1), 10000);
    }

    // returns memory usage in bytes, and the time complexity per insert.
    fn eval_cost(p: f64, q: f64) -> (usize, usize) {
        #[allow(non_snake_case)]
        // N = sum(actual)
        // Let's assume 1021 samples, all of 4096
        let N = 1021 * 4096;
        let sketch = CountMinSketch::with_params(p / N as f64, 1.0 - q, &mut rng());

        let memory = core::mem::size_of::<u32>() * sketch.buckets.len();
        let time = sketch.depth;
        (memory, time)
    }

    #[test]
    fn memory_usage() {
        assert_eq!(eval_cost(100.0, 0.99), (2273580, 5));
        assert_eq!(eval_cost(4096.0, 0.99), (55520, 5));
        assert_eq!(eval_cost(4096.0, 0.90), (33312, 3));
        assert_eq!(eval_cost(4096.0, 0.1), (11104, 1));

        let sketch = CountMinSketch::with_params(10.0 / 20_000.0, 0.01, &mut rng());

        let memory = core::mem::size_of::<u32>() * sketch.buckets.len();
        let memory2 = core::mem::size_of::<foldhash::quality::FixedState>() * sketch.hashers.len();
        let time = sketch.depth;
        std::println!("{} {time}", memory + memory2);
    }

    #[test]
    fn reset() {
        // fixed value of phi for consistent test
        let mut rng = StdRng::seed_from_u64(16180339887498948482);
        let mut sketch = CountMinSketch::with_params(1.0, 0.1, &mut rng);

        for i in 1..=5 {
            assert_eq!(sketch.count(&0), i);
        }
        sketch.reset(&mut rng);
        assert_eq!(sketch.count(&0), 1);
    }
}
