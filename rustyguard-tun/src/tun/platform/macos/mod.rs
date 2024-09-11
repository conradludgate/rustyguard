//! macOS specific functionality.

pub mod sys;

mod device;
pub use self::device::{Device, Queue};

use crate::tun::configuration::Configuration as C;
use crate::tun::error::*;

/// Create a TUN device with the given name.
pub fn create(configuration: &C) -> Result<Device> {
    Device::new(configuration)
}
