use pnet::packet::{icmp::{
    echo_request::MutableEchoRequestPacket,
    {IcmpPacket, IcmpTypes},
}, ipv4::MutableIpv4Packet};
use pnet::packet::Packet;
use raw_socket::{
    ffi::c_int,
    tokio::RawSocket,
    option::{Level, Name},
    {Domain, Protocol, Type},
};
use std::{sync::Arc, net::SocketAddr};
use structopt::StructOpt;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore};

const IP_TTL: c_int = 2;
const IP_HDR_LEN: usize = 20;
const ICMP_HDR_LEN: usize = 8;
const EMSGSIZE: i32 = 90;

#[derive(StructOpt)]
struct Opt {
    target: String,
    protocol: Option<String>,
    #[structopt(long)]
    pmtud: bool,
}

#[derive(Clone, Copy)]
enum TracerouteProtocol {
    Udp,
    Icmp,
}

impl TracerouteProtocol {
    fn from_str(protocol: &str) -> Self {
        match protocol {
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            _ => unreachable!(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let opt = Opt::from_args();

    let target = opt.target;
    let protocol = TracerouteProtocol::from_str(&opt.protocol.unwrap_or("udp".to_string()));
    let path_maximum_transmission_unit_discovery = opt.pmtud;

    let semaphore = Arc::new(Semaphore::new(4));
    let counter_mutex = Arc::new(Mutex::new(0u8));

    let mut tasks = vec![];
    let recv_task = tokio::spawn(receiver(Arc::clone(&semaphore)));

    for task in 0..255 {
        let target = target.clone();
        let semaphore = Arc::clone(&semaphore);
        let counter_mutex = Arc::clone(&counter_mutex);

        tasks.push(tokio::spawn(async move {
            if let Ok(permit) = semaphore.clone().acquire().await {
                let ttl = {
                    let mut counter = counter_mutex.lock().await;
                    *counter += 1;
                    *counter
                };

                match protocol {
                    TracerouteProtocol::Udp => {
                        let sock = UdpSocket::bind(format!("192.168.1.64:{}", 8000 + task))
                            .await
                            .unwrap();

                        sock.set_ttl(ttl as u32).unwrap();
                        sock.send_to(&[], (target, 33434)).await.unwrap();
                    }
                    TracerouteProtocol::Icmp => {
                        let sock =
                            RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into())
                                .unwrap();

                        let mut buf = [0u8; ICMP_HDR_LEN];
                        let icmp_packet = build_icmp_packet(&mut buf);

                        sock.set_sockopt(Level::IPV4, Name::from(IP_TTL), &(ttl as c_int))
                            .unwrap();
                        sock.send_to(icmp_packet.packet(), (target, 0))
                            .await
                            .unwrap();
                    }
                }

                permit.forget();
            }
        }));
    }

    if path_maximum_transmission_unit_discovery {
        tokio::spawn(path_mtu_discovery(target));
    }

    if let Ok(_) = recv_task.await {
        semaphore.close();
    }

    Ok(())
}

async fn receiver(semaphore: Arc<Semaphore>) -> Result<(), std::io::Error> {
    use dns_lookup::lookup_addr;

    let mut buf = [0u8; 1024];
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()).unwrap();

    loop {
        let (_bytes_received, addr) = sock.recv_from(&mut buf).await?;
        let packet = IcmpPacket::new(&buf[IP_HDR_LEN..]).unwrap();

        let reverse_dns_task =
            tokio::task::spawn_blocking(move || lookup_addr(&addr.clone().ip()).unwrap());
        let hostname = reverse_dns_task.await.unwrap();

        println!("{} ({:?})", hostname, addr);

        match packet.get_icmp_type() {
            IcmpTypes::TimeExceeded => semaphore.add_permits(1),
            IcmpTypes::EchoReply | IcmpTypes::DestinationUnreachable => break,
            _ => {}
        }
    }

    Ok(())
}

async fn path_mtu_discovery(target: String) {
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::from(255).into()).unwrap();

    sock.connect((target.clone(), 0)).await.unwrap();

    let mut mtu = 65535;

    for ttl in 1..256 {
        let mut buf = vec![0u8; mtu as usize];
        let ipv4_packet = build_ipv4_packet(&mut buf);

        sock.set_sockopt(Level::IPV4, Name::from(IP_TTL), &(ttl as c_int + 1))
            .unwrap();

        if let Err(e) = sock.send_to(ipv4_packet.packet(), (target.clone(), 0)).await {
            if let Some(code) = e.raw_os_error() {
                if code == EMSGSIZE {
                    mtu = sock.get_sockopt(Level::IPV4, Name::IP_MTU).unwrap();
                    
                    println!("PMTU at hop {} is {}", ttl, mtu);
                }
            }
        } else {
            break;
        }
    }
}

fn build_icmp_packet(buf: &mut [u8]) -> MutableEchoRequestPacket {
    use pnet::packet::icmp::{checksum, IcmpCode};

    let mut packet = MutableEchoRequestPacket::new(buf).unwrap();
    let seq_no = rand::random::<u16>();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));
    packet.set_sequence_number(seq_no);
    packet.set_identifier(0x1337);
    packet.set_checksum(checksum(&IcmpPacket::new(&packet.packet()).unwrap()));

    packet
}

fn build_ipv4_packet(buf: &mut [u8]) -> MutableIpv4Packet {
    use pnet::packet::ipv4::Ipv4Flags;

    let mut packet = MutableIpv4Packet::new(buf).unwrap();
    packet.set_flags(Ipv4Flags::DontFragment);

    packet
}