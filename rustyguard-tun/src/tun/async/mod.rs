//! Async specific modules.

use crate::tun::error;

use crate::tun::configuration::Configuration;
use crate::tun::platform::create;

mod device;
pub use self::device::AsyncDevice;

/// Create a TUN device with the given name.
pub fn create_as_async(configuration: &Configuration) -> Result<AsyncDevice, error::Error> {
    let device = create(configuration)?;
    AsyncDevice::new(device).map_err(|err| err.into())
}
