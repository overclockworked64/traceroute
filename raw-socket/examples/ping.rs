// Copyright (C) 2020 - Will Glozer. All rights reserved.

use std::convert::TryInto;
use std::net::SocketAddr;
use anyhow::Result;
use raw_socket::{Domain, Type, Protocol};
use raw_socket::tokio::RawSocket;

#[tokio::main]
async fn main() -> Result<()>  {
    let ip4   = Domain::ipv4();
    let dgram = Type::dgram();
    let icmp4 = Protocol::icmpv4();

    let sock = RawSocket::new(ip4, dgram, Some(icmp4))?;

    let ping = IcmpPacket::echo_request(1, 2, b"asdf");
    let dst  = SocketAddr::new("1.1.1.1".parse()?, 0);

    let mut buf = [0u8; 64];
    let pkt = ping.encode(&mut buf);
    sock.send_to(pkt, dst).await?;

    let mut buf = [0u8; 64];
    let (n, from) = sock.recv_from(&mut buf).await?;
    let pong = IcmpPacket::decode(&pkt[..n]);

    println!("{:?}: {:?}", from, pong);

    Ok(())
}

#[derive(Debug)]
enum IcmpPacket<'a> {
    EchoRequest(Echo<'a>),
    EchoReply(Echo<'a>),
}

#[derive(Debug)]
struct Echo<'a> {
    ident: u16,
    seq:   u16,
    body:  &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    const HEADER_SIZE: usize = 8;

    const ECHO_REPLY:   u8 = 0;
    const ECHO_REQUEST: u8 = 8;

    fn echo_request(ident: u16, seq: u16, body: &'a [u8]) -> Self {
        Self::EchoRequest(Echo::new(ident, seq, body))
    }

    fn encode<'b>(&self, pkt: &'b mut [u8]) -> &'b [u8] {
        match self {
            Self::EchoRequest(e) => e.encode(Self::ECHO_REQUEST, pkt),
            Self::EchoReply(e)   => e.encode(Self::ECHO_REPLY,   pkt),
        }
    }

    fn decode(pkt: &'a [u8]) -> Self {
        let kind = pkt[0];
        let code = pkt[1];
        match (kind, code) {
            (Self::ECHO_REPLY,   0) => Self::EchoReply(Echo::decode(pkt)),
            (Self::ECHO_REQUEST, 0) => Self::EchoRequest(Echo::decode(pkt)),
            other                   => panic!("unexpected ICMP msg {:?}", other),
        }
    }
}

impl<'a> Echo<'a> {
    fn new(ident: u16, seq: u16, body: &'a [u8]) -> Self {
        Self { ident, seq, body }
    }

    fn encode<'b>(&self, kind: u8, pkt: &'b mut [u8]) -> &'b [u8] {
        let code:  u8  = 0;
        let cksum: u16 = 0;

        let n = IcmpPacket::HEADER_SIZE + self.body.len();

        pkt[0..2].copy_from_slice(&[kind, code]);
        pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
        pkt[4..6].copy_from_slice(&self.ident.to_be_bytes());
        pkt[6..8].copy_from_slice(&self.seq.to_be_bytes());
        pkt[8..n].copy_from_slice(&self.body);

        &pkt[..n]
    }

    fn decode(pkt: &'a [u8]) -> Self {
        let ident = pkt[4..6].try_into().unwrap();
        let seq   = pkt[6..8].try_into().unwrap();

        Self {
            ident: u16::from_be_bytes(ident),
            seq:   u16::from_be_bytes(seq),
            body:  &pkt[8..],
        }
    }
}
