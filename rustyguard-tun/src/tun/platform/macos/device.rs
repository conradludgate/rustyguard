#![allow(unused_variables)]

use crate::tun::{
    configuration::Configuration,
    device::Device as D,
    error::*,
    platform::{
        macos::sys::*,
        posix::{Fd, SockAddr},
    },
};
use libc::{
    self, c_char, c_short, c_uint, c_void, sockaddr, socklen_t, AF_INET, AF_SYSTEM, AF_SYS_CONTROL,
    IFF_RUNNING, IFF_UP, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
};
use std::{
    ffi::CStr,
    io::{self, Read, Write},
    mem,
    net::Ipv4Addr,
    os::unix::io::{AsRawFd, IntoRawFd, RawFd},
    ptr,
};

/// A TUN device using the TUN macOS driver.
pub struct Device {
    pub(crate) name: String,
    pub(crate) queue: Queue,
    pub(crate) ctl: Fd,
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let id = if let Some(name) = config.name.as_ref() {
            if name.len() > IFNAMSIZ {
                return Err(Error::NameTooLong);
            }

            if !name.starts_with("utun") {
                return Err(Error::InvalidName);
            }

            name[4..].parse::<u32>()? + 1u32
        } else {
            0u32
        };

        let queues_number = config.queues.unwrap_or(1);
        if queues_number != 1 {
            return Err(Error::InvalidQueuesNumber);
        }

        let mut device = unsafe {
            let tun = Fd::new(libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL))?;

            let mut info = ctl_info {
                ctl_id: 0,
                ctl_name: {
                    let mut buffer = [0; 96];
                    for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut()) {
                        *o = *i as _;
                    }
                    buffer
                },
            };

            ctliocginfo(tun.0, &mut info as *mut _ as *mut _)?;

            let addr = sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM as _,
                ss_sysaddr: AF_SYS_CONTROL as _,
                sc_unit: id as c_uint,
                sc_reserved: [0; 5],
            };

            let address = &addr as *const sockaddr_ctl as *const sockaddr;
            if libc::connect(tun.0, address, mem::size_of_val(&addr) as socklen_t) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            let mut name = [0u8; 64];
            let mut name_len: socklen_t = 64;

            let optval = &mut name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(tun.0, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, optval, optlen) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            let ctl = Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0))?;

            Device {
                name: CStr::from_ptr(name.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .into(),
                queue: Queue { tun },
                ctl,
            }
        };

        device.configure(config)?;
        device.set_alias(
            config.address.unwrap_or(Ipv4Addr::new(10, 0, 0, 1)),
            config.destination.unwrap_or(Ipv4Addr::new(10, 0, 0, 255)),
            config.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
        )?;

        Ok(device)
    }

    /// Prepare a new request.
    /// # Safety
    pub unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(
            self.name.as_ptr() as *const c_char,
            req.ifrn.name.as_mut_ptr(),
            self.name.len(),
        );

        req
    }

    /// Set the IPv4 alias of the device.
    pub fn set_alias(&mut self, addr: Ipv4Addr, broadaddr: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req: ifaliasreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                self.name.as_ptr() as *const c_char,
                req.ifran.as_mut_ptr(),
                self.name.len(),
            );

            req.addr = SockAddr::from(addr).into();
            req.broadaddr = SockAddr::from(broadaddr).into();
            req.mask = SockAddr::from(mask).into();

            siocaifaddr(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> io::Result<()> {
        self.queue.set_nonblock()
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.queue.tun.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.queue.tun.read_vectored(bufs)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.queue.tun.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.queue.tun.flush()
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.queue.tun.write_vectored(bufs)
    }
}

impl D for Device {
    type Queue = Queue;

    fn enabled(&mut self, value: bool) -> Result<()> {
        unsafe {
            let mut req = self.request();

            siocgifflags(self.ctl.as_raw_fd(), &mut req)?;

            if value {
                req.ifru.flags |= (IFF_UP | IFF_RUNNING) as c_short;
            } else {
                req.ifru.flags &= !(IFF_UP as c_short);
            }

            siocsifflags(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_address(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.addr = SockAddr::from(value).into();

            siocsifaddr(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_destination(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.dstaddr = SockAddr::from(value).into();

            siocsifdstaddr(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_broadcast(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.broadaddr = SockAddr::from(value).into();

            siocsifbrdaddr(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.addr = SockAddr::from(value).into();

            siocsifnetmask(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    fn set_mtu(&mut self, value: i32) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.mtu = value;

            siocsifmtu(self.ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }
}

impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.queue.as_raw_fd()
    }
}

impl IntoRawFd for Device {
    fn into_raw_fd(self) -> RawFd {
        self.queue.into_raw_fd()
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
