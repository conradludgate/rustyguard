use std::{ffi, io, num};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid configuration")]
    InvalidConfig,

    #[error("not implementated")]
    NotImplemented,

    #[error("device name too long")]
    NameTooLong,

    #[error("invalid device name")]
    InvalidName,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid file descriptor")]
    InvalidDescriptor,

    #[error("unsuported network layer of operation")]
    UnsupportedLayer,

    #[error("invalid queues number")]
    InvalidQueuesNumber,

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Nul(#[from] ffi::NulError),

    #[error(transparent)]
    ParseNum(#[from] num::ParseIntError),

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error(transparent)]
    Nix(#[from] nix::Error),
}

pub type Result<T, E = Error> = ::std::result::Result<T, E>;
