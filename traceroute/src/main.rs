use itertools::Itertools;
use pnet::packet::{
    icmp::{
        echo_request::MutableEchoRequestPacket,
        IcmpCode, {IcmpPacket, IcmpTypes},
    },
    ipv4::MutableIpv4Packet,
    Packet,
};
use raw_socket::{
    ffi::c_int,
    option::{Level, Name},
    tokio::RawSocket,
    {Domain, Protocol, Type},
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use structopt::StructOpt;
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{error::TryRecvError, Receiver},
        Mutex, Semaphore,
    },
};

const IP_HDR_LEN: usize = 20;
const ICMP_HDR_LEN: usize = 8;
const EMSGSIZE: i32 = 90;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let options = Opt::from_args();

    let target = options.target;
    let protocol =
        TracerouteProtocol::from_str(&options.protocol.unwrap_or_else(|| "udp".to_string()));
    let pmtud = Arc::new(Mutex::new(options.pmtud));

    let semaphore = Arc::new(Semaphore::new(4));
    let ttl_mutex = Arc::new(Mutex::new(0u8));
    let mtu_mutex = Arc::new(Mutex::new(65535));
    let packets_recvd_mutex = Arc::new(Mutex::new(0));

    let mut recv_buf = [0u8; 1024];
    let recv_sock =
        Arc::new(RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()).unwrap());

    let (tx, rx) = tokio::sync::mpsc::channel(1024);

    let printer = tokio::spawn(printer(rx));
    let mut tasks = vec![];

    for _ in 0..255 {
        let tx = tx.clone();
        let target = target.clone();
        let semaphore = Arc::clone(&semaphore);
        let counter_mutex = Arc::clone(&ttl_mutex);
        let mtu_mutex = Arc::clone(&mtu_mutex);
        let packets_recvd_mutex = Arc::clone(&packets_recvd_mutex);
        let pmtud = Arc::clone(&pmtud);
        let recv_sock = Arc::clone(&recv_sock);

        tasks.push(tokio::spawn(async move {
            if let Ok(permit) = semaphore.clone().acquire().await {
                let ttl = {
                    let mut counter = counter_mutex.lock().await;
                    *counter += 1;
                    *counter
                };

                match protocol {
                    TracerouteProtocol::Udp => trace_udp(&target, ttl).await,
                    TracerouteProtocol::Icmp => trace_icmp(&target, ttl).await,
                }

                let path_maximum_transmission_unit_discovery = {
                    let guard = pmtud.lock().await;

                    *guard
                };

                let mtu = if path_maximum_transmission_unit_discovery {
                    path_mtu_discovery(target, Arc::clone(&mtu_mutex), ttl, Arc::clone(&pmtud))
                        .await
                } else {
                    0
                };

                let (_bytes_received, ip_addr) = recv_sock.recv_from(&mut recv_buf).await.unwrap();

                let mut packet_no = packets_recvd_mutex.lock().await;
                *packet_no += 1;

                let packet = IcmpPacket::new(&recv_buf[IP_HDR_LEN..]).unwrap();

                let reverse_dns_task = tokio::task::spawn_blocking(move || {
                    dns_lookup::lookup_addr(&ip_addr.clone().ip()).unwrap()
                });
                let hostname = reverse_dns_task.await.unwrap();

                let info = Info {
                    hostname,
                    ip_addr,
                    mtu,
                    ttl: *packet_no,
                };

                tx.send(Message::Some(info)).await.unwrap();

                match packet.get_icmp_type() {
                    IcmpTypes::TimeExceeded => semaphore.add_permits(1),
                    IcmpTypes::EchoReply | IcmpTypes::DestinationUnreachable => {
                        tx.send(Message::None).await.unwrap()
                    }
                    _ => {}
                }

                permit.forget();
            }
        }))
    }

    if printer.await.is_ok() {
        semaphore.close();
    }

    Ok(())
}

async fn trace_udp(target: &str, ttl: u8) {
    let sock = UdpSocket::bind("192.168.1.64:8000").await.unwrap();

    sock.set_ttl(ttl as u32).unwrap();
    sock.send_to(&[], (target, 33434)).await.unwrap();
}

async fn trace_icmp(target: &str, ttl: u8) {
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()).unwrap();

    let mut buf = [0u8; ICMP_HDR_LEN];
    let icmp_packet = build_icmp_packet(&mut buf);

    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &(ttl as c_int))
        .unwrap();
    sock.send_to(icmp_packet.packet(), (target, 0))
        .await
        .unwrap();
}

async fn printer(mut rx: Receiver<Message>) -> Result<(), std::io::Error> {
    let mut data = HashMap::new();

    'driver: loop {
        match rx.try_recv() {
            Ok(message) => match message {
                Message::Some(info) => {
                    data.insert(info.ttl, (info.hostname, info.ip_addr, info.mtu));
                }
                Message::None => {
                    let last_msg = data.keys().max().copied().unwrap();

                    for msg in 1..last_msg + 1 {
                        match data.get(&msg) {
                            Some(_) => {}
                            None => continue 'driver,
                        }
                    }

                    break;
                }
            },
            Err(e) => match e {
                TryRecvError::Empty => continue,
                TryRecvError::Disconnected => break,
            },
        }
    }

    let mut printed_ip_addrs = vec![];

    for ttl in data.keys().sorted() {
        let (hostname, ip_addr, mtu) = data.get(ttl).unwrap();
        if !printed_ip_addrs.contains(ip_addr) {
            printed_ip_addrs.push(*ip_addr);

            println!("{}: {} ({:?}) pmtu: {}", ttl, hostname, ip_addr, mtu);
        }
    }

    Ok(())
}

async fn path_mtu_discovery(
    target: String,
    mtu_mutex: Arc<Mutex<u16>>,
    ttl: u8,
    pmtud: Arc<Mutex<bool>>,
) -> u16 {
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::from(255).into()).unwrap();

    sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &(1i32))
        .unwrap();
    sock.connect((target.clone(), 0)).await.unwrap();

    let mut mtu = mtu_mutex.lock().await;

    let mut buf = vec![rand::random::<u8>(); *mtu as usize];
    let ipv4_packet = build_ipv4_packet(&mut buf, target.clone(), *mtu, ttl);

    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &(ttl as c_int + 1))
        .unwrap();

    match sock
        .send_to(ipv4_packet.packet(), (target.clone(), 0))
        .await
    {
        Ok(_) => {
            let mut path_maximum_transmission_unit_discovery = pmtud.lock().await;
            *path_maximum_transmission_unit_discovery = false;
        }
        Err(e) => {
            if let Some(code) = e.raw_os_error() {
                if code == EMSGSIZE {
                    *mtu = sock
                        .get_sockopt::<c_int>(Level::IPV4, Name::IP_MTU)
                        .unwrap() as u16;
                }
            }
        }
    }

    *mtu
}

fn build_ipv4_packet(buf: &mut [u8], dest: String, size: u16, ttl: u8) -> MutableIpv4Packet {
    use pnet::packet::ipv4::Ipv4Flags;

    let mut packet = MutableIpv4Packet::new(buf).unwrap();
    packet.set_version(4);
    packet.set_ttl(ttl);
    packet.set_header_length(5);
    packet.set_identification(0x1337);
    packet.set_source("192.168.1.64".parse::<Ipv4Addr>().unwrap());
    packet.set_destination(dest.parse::<Ipv4Addr>().unwrap());
    packet.set_flags(Ipv4Flags::DontFragment);
    packet.set_total_length(size);
    packet.set_payload(&vec![rand::random::<u8>(); size as usize - IP_HDR_LEN]);
    packet.set_checksum(pnet::packet::ipv4::checksum(&packet.to_immutable()));

    packet
}

fn build_icmp_packet(buf: &mut [u8]) -> MutableEchoRequestPacket {
    use pnet::packet::icmp::checksum;

    let mut packet = MutableEchoRequestPacket::new(buf).unwrap();
    let seq_no = rand::random::<u16>();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));
    packet.set_sequence_number(seq_no);
    packet.set_identifier(0x1337);
    packet.set_checksum(checksum(&IcmpPacket::new(packet.packet()).unwrap()));

    packet
}

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

#[derive(Debug)]
enum Message {
    Some(Info),
    None,
}

#[derive(Debug)]
struct Info {
    hostname: String,
    ip_addr: SocketAddr,
    mtu: u16,
    ttl: u8,
}
