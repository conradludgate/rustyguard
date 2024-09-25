// Copyright 2015-2021 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Error reporting.

extern crate std;

use core::error::Error;
use core::num::TryFromIntError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unspecified;

// This is required for the implementation of `core::error::Error`.
impl core::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("Unspecified")
    }
}

impl From<core::array::TryFromSliceError> for Unspecified {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Self
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeyRejected(&'static str);

impl KeyRejected {
    /// The value returned from `<Self as core::error::Error>::description()`
    #[must_use]
    pub fn description_(&self) -> &'static str {
        self.0
    }

    pub(crate) fn wrong_algorithm() -> Self {
        KeyRejected("WrongAlgorithm")
    }

    pub(crate) fn unexpected_error() -> Self {
        KeyRejected("UnexpectedError")
    }

    pub(crate) fn unspecified() -> Self {
        KeyRejected("Unspecified")
    }
}

impl Error for KeyRejected {
    fn description(&self) -> &str {
        self.description_()
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl Error for Unspecified {
    fn description(&self) -> &str {
        "Unspecified"
    }

    #[inline]
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl core::fmt::Display for KeyRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.description_())
    }
}

impl From<KeyRejected> for Unspecified {
    fn from(_: KeyRejected) -> Self {
        Unspecified
    }
}

impl From<()> for Unspecified {
    fn from((): ()) -> Self {
        Unspecified
    }
}

impl From<Unspecified> for () {
    fn from(_: Unspecified) -> Self {}
}

impl From<()> for KeyRejected {
    fn from((): ()) -> Self {
        KeyRejected::unexpected_error()
    }
}

impl From<TryFromIntError> for Unspecified {
    fn from(_: TryFromIntError) -> Self {
        Unspecified
    }
}

impl From<TryFromIntError> for KeyRejected {
    fn from(_: TryFromIntError) -> Self {
        KeyRejected::unexpected_error()
    }
}

impl From<Unspecified> for KeyRejected {
    fn from(_: Unspecified) -> Self {
        Self::unspecified()
    }
}

#[allow(deprecated, unused_imports)]
#[cfg(test)]
mod tests {
    use crate::error::KeyRejected;
    use crate::test;
    use core::error::Error;
    use std::format;

    #[test]
    fn display_unspecified() {
        let output = format!("{}", super::Unspecified);
        assert_eq!("Unspecified", output);
    }

    #[test]
    fn unexpected_error() {
        let key_rejected = super::KeyRejected::from(());
        assert_eq!("UnexpectedError", key_rejected.description());

        let unspecified = super::Unspecified::from(key_rejected);
        assert_eq!("Unspecified", unspecified.description());

        #[allow(clippy::redundant_locals)]
        let unspecified = unspecified;
        assert_eq!("Unspecified", unspecified.description());
    }

    #[test]
    fn std_error() {
        let key_rejected = KeyRejected::wrong_algorithm();
        assert!(key_rejected.cause().is_none());
        assert_eq!("WrongAlgorithm", key_rejected.description());

        let unspecified = super::Unspecified;
        assert!(unspecified.cause().is_none());
        assert_eq!("Unspecified", unspecified.description());

        test::compile_time_assert_std_error_error::<KeyRejected>();
    }
}
