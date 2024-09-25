// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::Unspecified;
use aws_lc::RAND_bytes;
use core::fmt::Debug;

/// A secure random number generator.
pub trait SecureRandom: sealed::SecureRandom {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    /// `error::Unspecified` if unable to fill `dest`.
    fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified>;
}

impl<T> SecureRandom for T
where
    T: sealed::SecureRandom,
{
    #[inline]
    fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        self.fill_impl(dest)
    }
}

// /// A random value constructed from a `SecureRandom` that hasn't been exposed
// /// through any safe Rust interface.
// ///
// /// Intentionally does not implement any traits other than `Sized`.
// pub struct Random<T: RandomlyConstructable>(T);

// impl<T: RandomlyConstructable> Random<T> {
//     /// Expose the random value.
//     #[inline]
//     pub fn expose(self) -> T {
//         self.0
//     }
// }

// /// Generate the new random value using `rng`.
// ///
// /// # Errors
// /// `error::Unspecified` if unable to fill buffer.
// #[inline]
// pub fn generate<T: RandomlyConstructable>(
//     rng: &dyn SecureRandom,
// ) -> Result<Random<T>, Unspecified> {
//     let mut r = T::zero();
//     rng.fill(r.as_mut_bytes())?;
//     Ok(Random(r))
// }

pub(crate) mod sealed {
    use crate::error;

    pub trait SecureRandom: core::fmt::Debug {
        /// Fills `dest` with random bytes.
        fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
    }

    // pub trait RandomlyConstructable: Sized {
    //     fn zero() -> Self;
    //     // `Default::default()`
    //     fn as_mut_bytes(&mut self) -> &mut [u8]; // `AsMut<[u8]>::as_mut`
    // }

    // impl<const T: usize> RandomlyConstructable for [u8; T] {
    //     #[inline]
    //     fn zero() -> Self {
    //         [0; T]
    //     }

    //     #[inline]
    //     fn as_mut_bytes(&mut self) -> &mut [u8] {
    //         &mut self[..]
    //     }
    // }
}

// /// A type that can be returned by `aws_lc_rs::rand::generate()`.
// pub trait RandomlyConstructable: sealed::RandomlyConstructable {}

// impl<T> RandomlyConstructable for T where T: sealed::RandomlyConstructable {}

/// A secure random number generator where the random values come from the
/// underlying *AWS-LC* libcrypto.
///
/// A single `SystemRandom` may be shared across multiple threads safely.
//
// # FIPS
// Use this implementation for retrieving random bytes.
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

impl sealed::SecureRandom for SystemRandom {
    #[inline]
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        fill(dest)
    }
}

/// Fills `dest` with random bytes.
///
// # FIPS
// Use this for retrieving random bytes or [`SystemRandom`].
//
/// # Errors
/// `error::Unspecified` if unable to fill `dest`.
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

    // #[test]
    // fn test_randomly_constructable() {
    //     let rando = SystemRandom::new();
    //     let random_array = generate(&rando).unwrap();
    //     let random_array: [u8; 173] = random_array.expose();
    //     let (mean, variance) = mean_variance(&mut random_array.into_iter());
    //     assert!((106f64..150f64).contains(&mean), "Mean: {mean}");
    //     assert!(variance > 8f64);
    //     println!("Mean: {mean} Variance: {variance}");
    // }

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
