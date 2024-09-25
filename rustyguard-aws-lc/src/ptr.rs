// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::{hint::unreachable_unchecked, ops::Deref};

use aws_lc::{
    EVP_AEAD_CTX_free, EVP_PKEY_CTX_free, EVP_PKEY_free, EVP_AEAD_CTX, EVP_PKEY, EVP_PKEY_CTX,
};

pub(crate) type LcPtr<T> = ManagedPointer<*mut T>;

#[derive(Debug)]
pub(crate) struct ManagedPointer<P: Pointer> {
    pointer: P,
}

impl<P: Pointer> ManagedPointer<P> {
    #[inline]
    pub fn new<T: IntoPointer<P>>(value: T) -> Result<Self, ()> {
        if let Some(pointer) = value.into_pointer() {
            Ok(Self { pointer })
        } else {
            Err(())
        }
    }
}

impl<P: Pointer> Drop for ManagedPointer<P> {
    #[inline]
    fn drop(&mut self) {
        self.pointer.free();
    }
}

impl<P: Pointer> ManagedPointer<P> {
    #[inline]
    pub fn as_const(&self) -> ConstPointer<P::T> {
        ConstPointer {
            ptr: self.pointer.as_const_ptr(),
        }
    }

    #[inline]
    pub unsafe fn as_mut_unsafe(&self) -> MutPointer<P::T> {
        MutPointer {
            ptr: self.pointer.as_const_ptr() as *mut P::T,
        }
    }

    #[inline]
    pub fn as_mut(&mut self) -> MutPointer<P::T> {
        MutPointer {
            ptr: self.pointer.as_mut_ptr(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) struct DetachablePointer<P: Pointer> {
    pointer: Option<P>,
}

impl<P: Pointer> Deref for DetachablePointer<P> {
    type Target = P;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.pointer {
            Some(pointer) => pointer,
            None => {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                unsafe { unreachable_unchecked() }
            }
        }
    }
}

impl<P: Pointer> From<DetachablePointer<P>> for ManagedPointer<P> {
    #[inline]
    fn from(mut dptr: DetachablePointer<P>) -> Self {
        match dptr.pointer.take() {
            Some(pointer) => ManagedPointer { pointer },
            None => {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                unsafe { unreachable_unchecked() }
            }
        }
    }
}

impl<P: Pointer> Drop for DetachablePointer<P> {
    #[inline]
    fn drop(&mut self) {
        if let Some(mut pointer) = self.pointer.take() {
            pointer.free();
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConstPointer<T> {
    ptr: *const T,
}

impl<T> Deref for ConstPointer<T> {
    type Target = *const T;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

#[derive(Debug)]
pub(crate) struct MutPointer<T> {
    ptr: *mut T,
}

impl<T> Deref for MutPointer<T> {
    type Target = *mut T;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

pub(crate) trait Pointer {
    type T;

    fn free(&mut self);
    fn as_const_ptr(&self) -> *const Self::T;
    fn as_mut_ptr(&mut self) -> *mut Self::T;
}

pub(crate) trait IntoPointer<P> {
    fn into_pointer(self) -> Option<P>;
}

impl<T> IntoPointer<*mut T> for *mut T {
    #[inline]
    fn into_pointer(self) -> Option<*mut T> {
        if self.is_null() {
            None
        } else {
            Some(self)
        }
    }
}

macro_rules! create_pointer {
    ($ty:ty, $free:path) => {
        impl Pointer for *mut $ty {
            type T = $ty;

            #[inline]
            fn free(&mut self) {
                unsafe {
                    let ptr = *self;
                    $free(ptr.cast());
                }
            }

            #[inline]
            fn as_const_ptr(&self) -> *const Self::T {
                self.cast()
            }

            #[inline]
            fn as_mut_ptr(&mut self) -> *mut Self::T {
                *self
            }
        }
    };
}

// `OPENSSL_free` and the other `XXX_free` functions perform a zeroization of the memory when it's
// freed. This is different than functions of the same name in OpenSSL which generally do not zero
// memory.
create_pointer!(EVP_PKEY, EVP_PKEY_free);
create_pointer!(EVP_PKEY_CTX, EVP_PKEY_CTX_free);
create_pointer!(EVP_AEAD_CTX, EVP_AEAD_CTX_free);
