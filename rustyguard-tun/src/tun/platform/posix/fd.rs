use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

use crate::tun::error::*;
use libc::{self, fcntl, F_GETFL, F_SETFL, O_NONBLOCK};

/// POSIX file descriptor support for `io` traits.
pub struct Fd(pub RawFd);

impl Fd {
    pub fn new(value: RawFd) -> Result<Self> {
        if value < 0 {
            return Err(Error::InvalidDescriptor);
        }

        Ok(Fd(value))
    }

    /// Enable non-blocking mode
    pub fn set_nonblock(&self) -> io::Result<()> {
        match unsafe { fcntl(self.0, F_SETFL, fcntl(self.0, F_GETFL) | O_NONBLOCK) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Read for Fd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let amount = libc::read(self.0, buf.as_mut_ptr() as *mut _, buf.len());

            if amount < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(amount as usize)
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        unsafe {
            let iov = bufs.as_ptr().cast();
            let iovcnt = bufs.len().min(libc::c_int::MAX as usize) as _;

            let n = libc::readv(self.0, iov, iovcnt);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(n as usize)
        }
    }
}

impl Write for Fd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let amount = libc::write(self.0, buf.as_ptr() as *const _, buf.len());

            if amount < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(amount as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        unsafe {
            let iov = bufs.as_ptr().cast();
            let iovcnt = bufs.len().min(libc::c_int::MAX as usize) as _;

            let n = libc::writev(self.0, iov, iovcnt);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(n as usize)
        }
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl IntoRawFd for Fd {
    fn into_raw_fd(mut self) -> RawFd {
        let fd = self.0;
        self.0 = -1;
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe {
            if self.0 >= 0 {
                libc::close(self.0);
            }
        }
    }
}
