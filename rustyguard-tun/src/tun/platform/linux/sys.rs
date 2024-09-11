//! Bindings to internal Linux stuff.

use libc::{c_int, ifreq};
use nix::{ioctl_read_bad, ioctl_write_ptr, ioctl_write_ptr_bad};

ioctl_read_bad!(siocgifflags, 0x8913, ifreq);
ioctl_write_ptr_bad!(siocsifflags, 0x8914, ifreq);
ioctl_read_bad!(siocgifaddr, 0x8915, ifreq);
ioctl_write_ptr_bad!(siocsifaddr, 0x8916, ifreq);
ioctl_read_bad!(siocgifdstaddr, 0x8917, ifreq);
ioctl_write_ptr_bad!(siocsifdstaddr, 0x8918, ifreq);
ioctl_read_bad!(siocgifbrdaddr, 0x8919, ifreq);
ioctl_write_ptr_bad!(siocsifbrdaddr, 0x891a, ifreq);
ioctl_read_bad!(siocgifnetmask, 0x891b, ifreq);
ioctl_write_ptr_bad!(siocsifnetmask, 0x891c, ifreq);
ioctl_read_bad!(siocgifmtu, 0x8921, ifreq);
ioctl_write_ptr_bad!(siocsifmtu, 0x8922, ifreq);
ioctl_write_ptr_bad!(siocsifname, 0x8923, ifreq);

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
ioctl_write_ptr!(tunsetpersist, b'T', 203, c_int);
ioctl_write_ptr!(tunsetowner, b'T', 204, c_int);
ioctl_write_ptr!(tunsetgroup, b'T', 206, c_int);
