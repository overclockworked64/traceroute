// Copyright (C) 2020 - Will Glozer. All rights reserved.

use std::io::IoSlice;
use std::net::SocketAddr;
use anyhow::Result;
use libc::c_int;
use raw_socket::prelude::*;

fn main() -> Result<()>  {
    let ip6   = Domain::ipv6();
    let dgram = Type::dgram();
    let udp   = Protocol::udp();

    let sock = RawSocket::new(ip6, dgram, Some(udp))?;

    let enable: c_int = 1;
    sock.set_sockopt(Level::IPV6, Name::IPV6_RECVPATHMTU, &enable)?;
    sock.set_sockopt(Level::IPV6, Name::IPV6_DONTFRAG,    &enable)?;

    let mut ctrl = [0u8; 64];
    let limit = CMsg::Ipv6HopLimit(5);
    let ctrl  = CMsg::encode(&mut ctrl, &[limit])?;

    let data = [0u8; 64];
    let data = IoSlice::new(&data[..]);

    let dst = SocketAddr::new("2606:4700:4700::1111".parse()?, 1234);
    sock.send_msg(dst, &[data], &ctrl)?;

    Ok(())
}
