// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::Unspecified;
use aws_lc::RAND_bytes;

/// A secure random number generator.
#[cfg(test)]
pub trait SecureRandom {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    /// `error::Unspecified` if unable to fill `dest`.
    fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified>;
}

#[derive(Clone, Debug)]
pub struct SystemRandom(());

const SYSTEM_RANDOM: SystemRandom = SystemRandom(());

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline]
    #[must_use]
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for SystemRandom {
    fn default() -> Self {
        SYSTEM_RANDOM
    }
}

#[cfg(test)]
impl SecureRandom for SystemRandom {
    #[inline]
    #[cfg(test)]
    fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        fill(dest)
    }
}

pub fn fill(dest: &mut [u8]) -> Result<(), Unspecified> {
    if 1 != (unsafe { RAND_bytes(dest.as_mut_ptr(), dest.len()) }) {
        return Err(Unspecified);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::rand;
    use core::array::IntoIter;
    use std::println;

    use crate::rand::{SecureRandom, SystemRandom};

    #[test]
    fn test_secure_random_fill() {
        let mut random_array = [0u8; 173];
        let rng = SystemRandom::new();
        rng.fill(&mut random_array).unwrap();

        let (mean, variance) = mean_variance(&mut random_array.into_iter());
        assert!((106f64..150f64).contains(&mean), "Mean: {mean}");
        assert!(variance > 8f64);
        println!("Mean: {mean} Variance: {variance}");
    }

    #[test]
    fn test_rand_fill() {
        let mut random_array: [u8; 173] = [0u8; 173];
        rand::fill(&mut random_array).unwrap();

        let (mean, variance) = mean_variance(&mut random_array.into_iter());
        assert!((106f64..150f64).contains(&mean), "Mean: {mean}");
        assert!(variance > 8f64);
        println!("Mean: {mean} Variance: {variance}");
    }

    fn mean_variance<T: Into<f64>, const N: usize>(iterable: &mut IntoIter<T, N>) -> (f64, f64) {
        let iter = iterable;
        let mean: Option<T> = iter.next();
        let mut mean = mean.unwrap().into();
        let mut var_squared = 0f64;
        let mut count = 1f64;
        for value in iter.by_ref() {
            count += 1f64;
            let value = value.into();
            let prev_mean = mean;
            mean = prev_mean + (value - prev_mean) / count;
            var_squared =
                var_squared + ((value - prev_mean) * (value - mean) - var_squared) / count;
        }

        (mean, var_squared.sqrt())
    }
}
