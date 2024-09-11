use std::net::Ipv4Addr;

use super::address::IntoAddress;

/// Configuration builder for a TUN interface.
#[derive(Clone, Default, Debug)]
pub struct Configuration {
    pub(crate) name: Option<String>,

    pub(crate) address: Option<Ipv4Addr>,
    pub(crate) destination: Option<Ipv4Addr>,
    pub(crate) broadcast: Option<Ipv4Addr>,
    pub(crate) netmask: Option<Ipv4Addr>,
    pub(crate) mtu: Option<i32>,
    pub(crate) enabled: Option<bool>,
    pub(crate) queues: Option<usize>,
}

impl Configuration {
    /// Set the address.
    pub fn address<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.address = Some(value.into_address().unwrap());
        self
    }

    /// Set the netmask.
    pub fn netmask<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.netmask = Some(value.into_address().unwrap());
        self
    }

    /// Set the interface to be enabled once created.
    pub fn up(&mut self) -> &mut Self {
        self.enabled = Some(true);
        self
    }

    // /// Set the interface to be disabled once created.
    // pub fn down(&mut self) -> &mut Self {
    //     self.enabled = Some(false);
    //     self
    // }
}
