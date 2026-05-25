//! Tools for runtime/alloc free conversion between
//! sync and async context

use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};

/// Future which only yield ready
/// with a copy of the inner value.
/// Can be polled by [poll_spin].
pub struct AlwaysReady<T>(T);

#[inline]
/// Convert a copy value to a future which
/// is always ready with a copy of the value
pub fn always_ready<T: Copy>(value: T) -> AlwaysReady<T> {
    AlwaysReady(value)
}

impl<T: Copy> Future for AlwaysReady<T> {
    type Output = T;
    #[inline]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<T> {
        Poll::Ready(self.0)
    }
}

#[inline]
/// Poll future in a spin loop to erase async coloring.
/// Use only for futures that will not yield pending
/// such as futures which only await [AlwaysReady].
pub fn poll_spin<T, F: Future<Output = T>>(f: F) -> T {
    let mut f = pin!(f);
    let mut noop_cx = Context::from_waker(Waker::noop());

    loop {
        let poll = f.as_mut().poll(&mut noop_cx);
        if let Poll::Ready(result) = poll {
            break result;
        }
    }
}
