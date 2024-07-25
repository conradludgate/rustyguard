use core::hash::Hash;

use rand_core::{CryptoRng, RngCore};

extern crate alloc;
use alloc::vec::Vec;

/// CountMinSketch is a fast, O(1) memory way to measure number of times we see a client
/// over time.
///
/// <https://en.wikipedia.org/wiki/Count%E2%80%93min_sketch>
pub struct CountMinSketch {
    // one for each depth
    hashers: Vec<ahash::RandomState>,
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
    /// where N is the cardinality of the stream
    ///
    /// example:
    /// Expecting 20,000 different IP addresses, and wanting a 95% accuracy of
    /// estimating the counts with +- 50 of the actual value, we have
    ///
    /// ```
    /// let δ = 0.05;
    /// let ε = 100.0 / 20_000.0;
    /// ```
    ///
    /// These parameters will use a total of 6,688 bytes.
    ///
    /// example:
    /// Expecting 20,000 different IP addresses, and wanting a 99% accuracy of
    /// estimating the counts with +- 5 of the actual value, we have
    ///
    /// ```
    /// let δ = 0.01;
    /// let ε = 10.0 / 20_000.0;
    /// ```
    ///
    /// These parameters will use a total of 108,964 bytes.
    pub fn with_params(epsilon: f64, delta: f64, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        CountMinSketch::new(
            (core::f64::consts::E / epsilon).ceil() as usize,
            (1.0_f64 / delta).ln().ceil() as usize,
            rng,
        )
    }

    fn new(width: usize, depth: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self {
            hashers: (0..depth)
                .map(|_| {
                    ahash::RandomState::with_seeds(
                        rng.next_u64(),
                        rng.next_u64(),
                        rng.next_u64(),
                        rng.next_u64(),
                    )
                })
                .collect(),
            width,
            depth,
            buckets: alloc::vec![0; width * depth],
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

    pub fn reset(&mut self) {
        self.buckets.clear();
        self.buckets.resize(self.width * self.depth, 0);
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use rand::{rngs::StdRng, seq::SliceRandom, thread_rng, Rng, SeedableRng};

    extern crate alloc;
    extern crate std;

    use super::CountMinSketch;

    fn eval_precision(n: usize, p: f64, q: f64) -> usize {
        // fixed value of phi for consistent test
        let mut rng = StdRng::seed_from_u64(16180339887498948482);

        #[allow(non_snake_case)]
        let mut N = 0;

        let mut ips = alloc::vec![];

        for _ in 0..n {
            // number of insert operations
            let n = rng.gen_range(1..10);

            let ip = Ipv4Addr::from_bits(rng.gen());
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
        let sketch = CountMinSketch::with_params(p / N as f64, 1.0 - q, &mut thread_rng());

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

        let sketch = CountMinSketch::with_params(10.0 / 20_000.0, 0.01, &mut thread_rng());

        let memory = core::mem::size_of::<u32>() * sketch.buckets.len();
        let memory2 = core::mem::size_of::<ahash::RandomState>() * sketch.hashers.len();
        let time = sketch.depth;
        std::println!("{} {time}", memory + memory2);
    }
}
