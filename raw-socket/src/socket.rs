// Copyright (C) 2020 - Will Glozer. All rights reserved.

use std::io::{Error, ErrorKind, IoSlice, IoSliceMut, Result};
use std::mem::{size_of, transmute, zeroed};
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::io::{AsRawFd, RawFd};
use libc::{AF_INET, AF_INET6, c_int, msghdr, sockaddr_storage, socklen_t};
use socket2::{Socket, SockAddr};
use crate::{Domain, Type, Protocol};
use crate::option::{Level, Name, Opt};

pub struct RawSocket {
    sys: Socket,
}

impl RawSocket {
    pub fn new(domain: Domain, kind: Type, protocol: Option<Protocol>) -> Result<Self> {
        let sys = Socket::new(domain, kind, protocol)?;
        Ok(Self { sys })
    }

    pub fn bind<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        self.sys.bind(&sockaddr(addr)?)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        socketaddr(&self.sys.local_addr()?)
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (n, addr) = self.sys.recv_from(buf)?;
        Ok((n, socketaddr(&addr)?))
    }

    pub fn recv_msg(
        &self,
        data: &[IoSliceMut<'_>],
        ctrl: &mut [u8]
    ) -> Result<(usize, SocketAddr)> {
        let fd = self.as_raw_fd();
        unsafe {
            let mut addr: sockaddr_storage = zeroed();
            let addr    = &mut addr as *mut _;
            let addrlen = size_of::<sockaddr_storage>();

            let mut msg: msghdr = zeroed();
            msg.msg_name    = addr          as *mut _;
            msg.msg_namelen = addrlen       as      _;
            msg.msg_iov     = data.as_ptr() as *mut _;
            msg.msg_iovlen  = data.len()    as      _;

            if !ctrl.is_empty() {
                msg.msg_control    = ctrl.as_ptr() as *mut _;
                msg.msg_controllen = ctrl.len()    as      _;
            }

            let n = match libc::recvmsg(fd, &mut msg, 0) {
                n if n >= 0 => n as usize,
                _           => Err(Error::last_os_error())?,
            };

            let addr = msg.msg_name as *const _;
            let len  = msg.msg_namelen;
            let addr = socketaddr(&SockAddr::from_raw_parts(addr, len))?;

            Ok((n, addr))
        }
    }

    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> Result<usize> {
        self.sys.send_to(buf, &sockaddr(addr)?)
    }

    pub fn send_msg<A: ToSocketAddrs>(
        &self,
        addr: A,
        data: &[IoSlice<'_>],
        ctrl: &[u8],
    ) -> Result<usize> {
        let fd   = self.as_raw_fd();
        let addr = sockaddr(addr)?;

        unsafe {
            let mut msg: msghdr = zeroed();
            msg.msg_name    = addr.as_ptr() as      _;
            msg.msg_namelen = addr.len()    as      _;
            msg.msg_iov     = data.as_ptr() as *mut _;
            msg.msg_iovlen  = data.len()    as      _;

            if !ctrl.is_empty() {
                msg.msg_control    = ctrl.as_ptr() as *mut _;
                msg.msg_controllen = ctrl.len()    as      _;
            }

            match libc::sendmsg(fd, &msg, 0) {
                n if n >= 0 => Ok(n as usize),
                _           => Err(Error::last_os_error()),
            }
        }
    }

    pub fn get_sockopt<O: Opt>(&self, level: Level, name: Name) -> Result<O> {
        let fd = self.as_raw_fd();

        let mut val = O::default();
        let mut len = size_of::<O>() as socklen_t;

        let ptr = &mut val as *mut _ as *mut _;
        let len = &mut len as *mut _;

        unsafe {
            let level = transmute(level);
            let name  = transmute(name);
            match libc::getsockopt(fd, level, name, ptr, len) {
                0 => Ok(val),
                _ => Err(Error::last_os_error()),
            }
        }
    }

    pub fn set_sockopt<O: Opt>(&self, level: Level, name: Name, value: &O) -> Result<()> {
        let fd  = self.as_raw_fd();
        let ptr = value as *const _ as *const _;
        let len = size_of::<O>() as socklen_t;

        unsafe {
            let level = transmute(level);
            let name  = transmute(name);
            match libc::setsockopt(fd, level, name, ptr, len) {
                0 => Ok(()),
                _ => Err(Error::last_os_error()),
            }
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.sys.set_nonblocking(nonblocking)
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.sys.as_raw_fd()
    }
}

fn sockaddr<A: ToSocketAddrs>(addr: A) -> Result<SockAddr> {
    match addr.to_socket_addrs()?.next() {
        Some(addr) => Ok(SockAddr::from(addr)),
        None       => Err(Error::new(ErrorKind::InvalidInput, "invalid socket address")),
    }
}

fn socketaddr(addr: &SockAddr) -> Result<SocketAddr> {
    match addr.family() as c_int {
        AF_INET  => Ok(addr.as_inet().expect("AF_INET addr").into()),
        AF_INET6 => Ok(addr.as_inet6().expect("AF_INET6 addr").into()),
        _        => Err(Error::new(ErrorKind::Other, "unknown address type")),
    }
}
