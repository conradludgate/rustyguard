//! Platform specific modules.

#[cfg(unix)]
pub mod posix;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::{create, Device, Queue, KERNEL_HEADER_LEN};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::{create, Device, Queue, KERNEL_HEADER_LEN};
