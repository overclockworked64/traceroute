// Copyright (C) 2020 - Will Glozer. All rights reserved.

#![allow(dead_code)]

pub use libc::c_int;
pub use libc::c_uint;
pub use libc::cmsghdr;
pub use libc::in6_pktinfo;
pub use libc::msghdr;

pub use libc::CMSG_DATA;
pub use libc::CMSG_LEN;
pub use libc::CMSG_SPACE;
pub use libc::CMSG_FIRSTHDR;
pub use libc::CMSG_NXTHDR;

pub use libc::IPPROTO_IP;
pub use libc::IPPROTO_IPV6;

pub use libc::IP_HDRINCL;
pub use libc::IPV6_PKTINFO;
pub use libc::IPV6_RECVPKTINFO;

pub use libc::SOL_SOCKET;

pub const IPV6_DONTFRAG: c_int = 62;

pub use sys::*;

#[cfg(target_os = "freebsd")]
#[path = "freebsd.rs"]
mod sys;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod sys;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod sys;

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "linux",
    target_os = "macos",
)))]
#[path = "other.rs"]
mod sys;
