// Copyright (C) 2020 - Will Glozer. All rights reserved.

use std::fmt;
use std::iter;
use std::mem::{size_of, zeroed};
use std::net::Ipv6Addr;
use std::ptr;
use std::slice;
use crate::ffi::*;

#[derive(Debug)]
pub enum CMsg<'a> {
    Ipv6HopLimit(c_int),
    Ipv6PathMtu(c_int),
    Ipv6PktInfo(Ipv6PktInfo),
    Raw(Raw<'a>),
}

pub struct Ipv6PktInfo(in6_pktinfo);

#[derive(Debug)]
pub struct Raw<'a> {
    pub level: c_int,
    pub kind:  c_int,
    pub data:  &'a [u8],
}

#[derive(Copy, Clone, Debug)]
pub enum Error {
    BufferSize,
}

impl<'a> CMsg<'a> {
    pub fn encode<'b>(buf: &'b mut [u8], msgs: &[CMsg]) -> Result<&'b [u8], Error> {
        let mut n = 0;

        unsafe {
            let mut root   = message_header(buf);
            let mut header = first_header(&mut root)?;

            for msg in msgs {
                let len = msg.size() as _;

                (*header).cmsg_len   = CMSG_LEN(len) as _;
                (*header).cmsg_level = msg.level();
                (*header).cmsg_type  = msg.kind();

                msg.write(CMSG_DATA(header));

                n += CMSG_SPACE(len) as usize;

                header = next_header(&root, header)?;
            }
        }

        Ok(&buf[..n])
    }

    pub fn decode<'b>(buf: &'b [u8]) -> impl Iterator<Item = CMsg<'b>> {
        unsafe {
            let mut root = message_header(buf);
            let mut next = first_header(&mut root);

            iter::from_fn(move || {
                let header = next.ok()?;

                let len   = (*header).cmsg_len;
                let level = (*header).cmsg_level;
                let kind  = (*header).cmsg_type;

                let ptr = CMSG_DATA(header);
                let len = len as usize;

                next = next_header(&root, header);

                Self::read(level, kind, ptr, len)
            })
        }
    }

    fn level(&self) -> c_int {
        match self {
            Self::Ipv6HopLimit(..) => IPPROTO_IPV6,
            Self::Ipv6PathMtu(..)  => IPPROTO_IPV6,
            Self::Ipv6PktInfo(..)  => IPPROTO_IPV6,
            Self::Raw(raw)         => raw.level,
        }
    }

    fn kind(&self) -> c_int {
        match self {
            Self::Ipv6HopLimit(..) => IPV6_HOPLIMIT,
            Self::Ipv6PathMtu(..)  => IPV6_PATHMTU,
            Self::Ipv6PktInfo(..)  => IPV6_PKTINFO,
            Self::Raw(raw)         => raw.kind,
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Ipv6HopLimit(..) => size_of::<c_int>(),
            Self::Ipv6PathMtu(..)  => size_of::<c_int>(),
            Self::Ipv6PktInfo(..)  => size_of::<in6_pktinfo>(),
            Self::Raw(raw)         => raw.data.len(),
        }
    }

    unsafe fn read<'b>(level: c_int, kind: c_int, ptr: *const u8, len: usize) -> Option<CMsg<'b>> {
        const INVALID: c_int = 0;

        Some(match (level, kind) {
            (IPPROTO_IPV6, IPV6_HOPLIMIT) => CMsg::Ipv6HopLimit(read(ptr)),
            (IPPROTO_IPV6, IPV6_PATHMTU ) => CMsg::Ipv6PathMtu(read(ptr)),
            (IPPROTO_IPV6, IPV6_PKTINFO ) => Ipv6PktInfo(read(ptr)).into(),
            (INVALID     , INVALID      ) => return None,
            (_           , _            ) => Raw::read(level, kind, ptr, len).into(),
        })
    }

    unsafe fn write(&self, ptr: *mut u8) {
        match self {
            Self::Ipv6HopLimit(limit) => write(ptr, limit.to_le()),
            Self::Ipv6PathMtu(mtu)    => write(ptr, mtu),
            Self::Ipv6PktInfo(info)   => write(ptr, info.0),
            Self::Raw(raw)            => raw.write(ptr),
        }
    }
}

unsafe fn message_header(buf: &[u8]) -> msghdr {
    let mut msg: msghdr = zeroed();
    msg.msg_control     = buf.as_ptr() as *mut _;
    msg.msg_controllen  = buf.len()    as      _;
    msg
}

unsafe fn first_header(msg: &mut msghdr) -> Result<*mut cmsghdr, Error> {
    match CMSG_FIRSTHDR(msg) {
        ptr if ptr.is_null() => Err(Error::BufferSize),
        ptr                  => Ok(ptr),
    }
}

unsafe fn next_header(msg: &msghdr, cmsg: *const cmsghdr) -> Result<*mut cmsghdr, Error> {
    match CMSG_NXTHDR(msg, cmsg) {
        ptr if ptr.is_null() => Err(Error::BufferSize),
        ptr                  => Ok(ptr),
    }
}

unsafe fn read<T>(src: *const u8) -> T {
    ptr::read_unaligned(src as *const T)
}

unsafe fn write<T>(dst: *mut u8, src: T) {
    ptr::write_unaligned(dst as *mut T, src);
}

impl Ipv6PktInfo {
    pub fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.0.ipi6_addr.s6_addr)
    }

    pub fn ifindex(&self) -> u32 {
        self.0.ipi6_ifindex as u32
    }
}

impl<'a> Raw<'a> {
    pub const fn from(level: c_int, kind: c_int, data: &'a [u8]) -> Self {
        Self { level, kind, data }
    }

    unsafe fn read(level: c_int, kind: c_int, ptr: *const u8, len: usize) -> Self {
        let len  = len - size_of::<cmsghdr>();
        let data = slice::from_raw_parts(ptr, len);
        Self { level, kind, data }
    }

    unsafe fn write(&self, ptr: *mut u8) {
        let src = self.data.as_ptr();
        let len = self.data.len();
        ptr::copy_nonoverlapping(src, ptr, len);
    }
}

impl<'a> From<Ipv6PktInfo> for CMsg<'a> {
    fn from(info: Ipv6PktInfo) -> Self {
        Self::Ipv6PktInfo(info)
    }
}

impl<'a> From<Raw<'a>> for CMsg<'a> {
    fn from(raw: Raw<'a>) -> Self {
        Self::Raw(raw)
    }
}

impl fmt::Debug for Ipv6PktInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr  = self.addr();
        let ifidx = self.ifindex();
        write!(f, "{{ addr: {}, ifindex: {} }}", addr, ifidx)
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
