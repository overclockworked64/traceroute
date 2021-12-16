use pnet::packet::{
    icmp::{
        echo_request::MutableEchoRequestPacket,
        {IcmpPacket, IcmpTypes}
    },
    ipv4::MutableIpv4Packet,
    Packet,
};
use raw_socket::{
    ffi::c_int,
    tokio::RawSocket,
    option::{Level, Name},
    {Domain, Protocol, Type},
};
use std::{
    sync::Arc,
    collections::HashMap,
    net::{SocketAddr, Ipv4Addr}
};
use structopt::StructOpt;
use tokio::{
    net::UdpSocket,
    sync::{
        Mutex, Semaphore,
        mpsc::{Sender, Receiver},
    }
};


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
    let pmtud = Arc::new(Mutex::new(opt.pmtud));

    let semaphore = Arc::new(Semaphore::new(4));
    let counter_mutex = Arc::new(Mutex::new(0u8));

    let (tx, rx) = tokio::sync::mpsc::channel(1024);

    let mut tasks = vec![];
    let recv_task = tokio::spawn(receiver(tx.clone(), Arc::clone(&semaphore)));
    let _printer_task = tokio::spawn(printer(rx));

    let mtu = 65535;

    for task in 0..255 {
        let target = target.clone();
        let semaphore = Arc::clone(&semaphore);
        let counter_mutex = Arc::clone(&counter_mutex);
        let tx = tx.clone();
        let pmtud = Arc::clone(&pmtud);

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

                        sock.set_sockopt(Level::IPV4, Name::IP_TTL, &(ttl as c_int))
                            .unwrap();
                        sock.send_to(icmp_packet.packet(), (target.clone(), 0))
                            .await
                            .unwrap();

                        let path_maximum_transmission_unit_discovery = {
                            let guard = pmtud.lock().await;
                            
                            *guard
                        };

                        if path_maximum_transmission_unit_discovery {
                            tokio::spawn(path_mtu_discovery(tx.clone(), target, mtu, ttl, Arc::clone(&pmtud)));
                        }
                    }
                }

                permit.forget();
            }
        }));
    }

    if let Ok(_) = recv_task.await {
        semaphore.close();
    }

    Ok(())
}

async fn receiver(tx: Sender<Message>, semaphore: Arc<Semaphore>) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 1024];
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()).unwrap();

    loop {
        let (_bytes_received, ip_addr) = sock.recv_from(&mut buf).await?;
        let packet = IcmpPacket::new(&buf[IP_HDR_LEN..]).unwrap();

        let reverse_dns_task =
            tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_addr.clone().ip()).unwrap());
        let hostname = reverse_dns_task.await.unwrap();

        let info = Info {
            hostname: Some(hostname),
            ip_addr: Some(ip_addr),
            ttl: None,
            mtu: None,
        };

        tx.send(Message::Some(info)).await.unwrap();

        match packet.get_icmp_type() {
            IcmpTypes::TimeExceeded => semaphore.add_permits(1),
            IcmpTypes::EchoReply | IcmpTypes::DestinationUnreachable => {
                tx.send(Message::None).await.unwrap();
                break;
            },
            _ => {}
        }
    }

    Ok(())
}

async fn path_mtu_discovery(tx: Sender<Message>, target: String, mut mtu: u16, ttl: u8, pmtud: Arc<Mutex<bool>>) {
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::from(255).into()).unwrap();

    sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &(1 as c_int)).unwrap();
    sock.connect((target.clone(), 0)).await.unwrap();
  
    let mut buf = vec![rand::random::<u8>(); mtu as usize];
    let ipv4_packet = build_ipv4_packet(&mut buf, target.clone(), mtu, ttl);

    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &(ttl as c_int + 1))
        .unwrap();

    if let Err(e) = sock.send_to(ipv4_packet.packet(), (target.clone(), 0)).await {
        if let Some(code) = e.raw_os_error() {
            if code == EMSGSIZE {
                mtu = sock.get_sockopt::<c_int>(Level::IPV4, Name::IP_MTU).unwrap() as u16;
                
                let message = Info {
                    hostname: None,
                    ip_addr: None,
                    ttl: Some(ttl),
                    mtu: Some(mtu),
                };

                tx.send(Message::Some(message)).await.unwrap();
            }
        }
    } else {
        let mut guard = pmtud.lock().await;
        *guard = false;
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

async fn printer(mut rx: Receiver<Message>) {
    let mut data = vec![];
    let mut mtus = HashMap::new();

    loop {
        if let Some(message) = rx.recv().await {
            match message {
                Message::Some(info) => {
                    if info.mtu.is_none() {
                        data.push((info.ip_addr, info.hostname, info.mtu));
                    } else {
                        mtus.insert(info.ttl, info.mtu);
                    }
                },
                Message::None => break,
            }
        }
    }

    for (ttl, mtu) in mtus {
        if let Some(datum) = data.get_mut(ttl.unwrap() as usize - 1) {
            datum.2 = mtu;
        }
    }

    for (ip_addr, hostname, mtu) in data {
        println!("{} ({:?}) pmtu {}", hostname.unwrap(), ip_addr.unwrap(), mtu.unwrap());
    }

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

#[derive(Debug)]
enum Message {
    Some(Info),
    None,
}

#[derive(Debug)]
struct Info {
    hostname: Option<String>,
    ip_addr: Option<SocketAddr>,
    ttl: Option<u8>,
    mtu: Option<u16>,
}