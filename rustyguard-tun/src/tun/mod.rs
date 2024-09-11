mod error;
// pub use error::*;

mod address;
// pub use address::IntoAddress;

mod device;
// pub use device::Device;

mod configuration;
pub use configuration::Configuration;

pub mod platform;
// pub use platform::create;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod r#async;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use r#async::*;

// pub fn configure() -> Configuration {
//     Configuration::default()
// }
