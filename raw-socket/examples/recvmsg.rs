// Copyright (C) 2020 - Will Glozer. All rights reserved.

use std::io::IoSliceMut;
use std::net::SocketAddr;
use anyhow::Result;
use libc::c_int;
use raw_socket::tokio::prelude::*;

#[tokio::main]
async fn main() -> Result<()>  {
    let ip6   = Domain::ipv6();
    let dgram = Type::dgram();
    let udp   = Protocol::udp();

    let sock = RawSocket::new(ip6, dgram, Some(udp))?;
    let addr = SocketAddr::new("::".parse()?, 1234);
    sock.bind(&addr).await?;

    let enable: c_int = 1;
    sock.set_sockopt(Level::IPV6, Name::IPV6_RECVHOPLIMIT, &enable)?;
    sock.set_sockopt(Level::IPV6, Name::IPV6_RECVPATHMTU,  &enable)?;
    sock.set_sockopt(Level::IPV6, Name::IPV6_RECVPKTINFO,  &enable)?;

    let mut data = [0u8; 64];
    let mut ctrl = [0u8; 64];

    loop {
        let iovec = &[IoSliceMut::new(&mut data)];
        let (n, from) = sock.recv_msg(iovec, Some(&mut ctrl)).await?;
        let cmsgs = CMsg::decode(&mut ctrl).collect::<Vec<_>>();
        println!("{:?}: {:?}: {:?}", from, &data[..n], cmsgs);
    }
}
