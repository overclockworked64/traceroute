// Copyright (C) 2020 - Will Glozer. All rights reserved.

use libc::{self, c_int};
use crate::ffi;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Level(c_int);

impl Level {
    pub const IPV4:   Level = Level(ffi::IPPROTO_IP);
    pub const IPV6:   Level = Level(ffi::IPPROTO_IPV6);
    pub const SOCKET: Level = Level(ffi::SOL_SOCKET);

    pub const fn from(n: c_int) -> Self {
        Self(n)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Name(c_int);

impl Name {
    pub const IPV4_HDRINCL:      Name = Name(ffi::IP_HDRINCL);
    pub const IPV6_CHECKSUM:     Name = Name(ffi::IPV6_CHECKSUM);
    pub const IPV6_RECVHOPLIMIT: Name = Name(ffi::IPV6_RECVHOPLIMIT);
    pub const IPV6_RECVPATHMTU:  Name = Name(ffi::IPV6_RECVPATHMTU);
    pub const IPV6_RECVPKTINFO:  Name = Name(ffi::IPV6_RECVPKTINFO);
    pub const IPV6_DONTFRAG:     Name = Name(ffi::IPV6_DONTFRAG);

    pub const SO_TYPE:           Name = Name(libc::SO_TYPE);
    pub const SO_KEEPALIVE:      Name = Name(libc::SO_KEEPALIVE);
    pub const SO_SNDBUF:         Name = Name(libc::SO_SNDBUF);
    pub const SO_RCVBUF:         Name = Name(libc::SO_RCVBUF);

    pub const fn from(n: c_int) -> Self {
        Self(n)
    }
}

pub unsafe trait Opt: Copy + Default {}

unsafe impl Opt for c_int {}
