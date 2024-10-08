use libc::{
    self, c_char, c_short, ifreq, AF_INET, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_RUNNING, IFF_TUN,
    IFF_UP, IFNAMSIZ, O_RDWR, SOCK_DGRAM,
};
use std::{
    ffi::{CStr, CString},
    io::{self, Read, Write},
    mem,
    net::Ipv4Addr,
    os::unix::io::{AsRawFd, IntoRawFd, RawFd},
    ptr,
    vec::Vec,
};

use crate::tun::{
    configuration::Configuration,
    device::Device as D,
    error::*,
    platform::linux::sys::*,
    platform::posix::{Fd, SockAddr},
};

/// A TUN device using the TUN/TAP Linux driver.
pub struct Device {
    name: String,
    pub(crate) queues: Vec<Queue>,
    ctl: Fd,
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let mut device = unsafe {
            let dev = match config.name.as_ref() {
                Some(name) => {
                    let name = CString::new(name.clone())?;

                    if name.as_bytes_with_nul().len() > IFNAMSIZ {
                        return Err(Error::NameTooLong);
                    }

                    Some(name)
                }

                None => None,
            };

            let mut queues = Vec::new();

            let mut req: ifreq = mem::zeroed();

            if let Some(dev) = dev.as_ref() {
                ptr::copy_nonoverlapping(
                    dev.as_ptr() as *const c_char,
                    req.ifr_name.as_mut_ptr(),
                    dev.as_bytes().len(),
                );
            }

            let device_type: c_short = IFF_TUN as c_short;

            let queues_num = config.queues.unwrap_or(1);
            if queues_num < 1 {
                return Err(Error::InvalidQueuesNumber);
            }

            let iff_no_pi = IFF_NO_PI as c_short;
            let iff_multi_queue = IFF_MULTI_QUEUE as c_short;
            req.ifr_ifru.ifru_flags =
                device_type | iff_no_pi | if queues_num > 1 { iff_multi_queue } else { 0 };

            for _ in 0..queues_num {
                let tun = Fd::new(libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR))
                    .map_err(|_| io::Error::last_os_error())?;

                tunsetiff(tun.0, &mut req as *mut _ as *mut _)?;

                queues.push(Queue { tun });
            }

            let ctl = Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0))?;

            let name = CStr::from_ptr(req.ifr_name.as_ptr())
                .to_string_lossy()
                .to_string();
            Device { name, queues, ctl }
        };

        device.configure(config)?;

        Ok(device)
    }

    /// Prepare a new request.
    unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(
            self.name.as_ptr() as *const c_char,
            req.ifr_name.as_mut_ptr(),
            self.name.len(),
        );

        req
    }

    // /// Make the device persistent.
    // pub fn persist(&mut self) -> Result<()> {
    //     unsafe {
    //         tunsetpersist(self.as_raw_fd(), &1)?;
    //         Ok(())
    //     }
    // }

    // /// Set the owner of the device.
    // pub fn user(&mut self, value: i32) -> Result<()> {
    //     unsafe {
    //         tunsetowner(self.as_raw_fd(), &value)?;
    //         Ok(())
    //     }
    // }

    // /// Set the group of the device.
    // pub fn group(&mut self, value: i32) -> Result<()> {
    //     unsafe {
    //         tunsetgroup(self.as_raw_fd(), &value)?;
    //         Ok(())
    //     }
    // }

    // /// Return whether the device has packet information
    // pub fn has_packet_information(&mut self) -> bool {
    //     self.queues[0].has_packet_information()
    // }

    // /// Split the interface into a `Reader` and `Writer`.
    // pub fn split(mut self) -> (posix::Reader, posix::Writer) {
    //     let fd = Arc::new(self.queues.swap_remove(0).tun);
    //     (posix::Reader(fd.clone()), posix::Writer(fd.clone()))
    // }

    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> io::Result<()> {
        self.queues[0].set_nonblock()
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.queues[0].read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.queues[0].read_vectored(bufs)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.queues[0].write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.queues[0].flush()
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.queues[0].write_vectored(bufs)
    }
}

impl D for Device {
    type Queue = Queue;

    fn enabled(&mut self, value: bool) -> Result<()> {
        unsafe {
            let mut req = self.request();

            siocgifflags(self.ctl.as_raw_fd(), &mut req)?;

            if value {
                req.ifr_ifru.ifru_flags |= (IFF_UP | IFF_RUNNING) as c_short;
            } else {
                req.ifr_ifru.ifru_flags &= !(IFF_UP as c_short);
            }

            siocsifflags(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_address(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_addr = SockAddr::from(value).into();

            siocsifaddr(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_destination(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_dstaddr = SockAddr::from(value).into();

            siocsifdstaddr(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_broadcast(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_broadaddr = SockAddr::from(value).into();

            siocsifbrdaddr(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_netmask = SockAddr::from(value).into();

            siocsifnetmask(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_mtu(&mut self, value: i32) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_mtu = value;

            siocsifmtu(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }
}

impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.queues[0].as_raw_fd()
    }
}

impl IntoRawFd for Device {
    fn into_raw_fd(mut self) -> RawFd {
        // It is Ok to swap the first queue with the last one, because the self will be dropped afterwards
        let queue = self.queues.swap_remove(0);
        queue.into_raw_fd()
    }
}

pub struct Queue {
    pub(crate) tun: Fd,
}

impl Queue {
    pub fn set_nonblock(&self) -> io::Result<()> {
        self.tun.set_nonblock()
    }
}

impl Read for Queue {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.tun.read_vectored(bufs)
    }
}

impl Write for Queue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tun.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tun.flush()
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.tun.write_vectored(bufs)
    }
}

impl AsRawFd for Queue {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

impl IntoRawFd for Queue {
    fn into_raw_fd(self) -> RawFd {
        self.tun.into_raw_fd()
    }
}
