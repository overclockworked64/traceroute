use itertools::Itertools;
use pnet::packet::{
    icmp::{
        echo_request::MutableEchoRequestPacket,
        IcmpCode, {IcmpPacket, IcmpTypes},
    },
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    Packet,
};
use raw_socket::{
    ffi::c_int,
    option::{Level, Name},
    tokio::RawSocket,
    {Domain, Protocol, Type},
};
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};
use structopt::StructOpt;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, Semaphore},
};

const IP_HDR_LEN: usize = 20;
const ICMP_HDR_LEN: usize = 8;
const EMSGSIZE: i32 = 90;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let options = Opt::from_args();

    let target = options.target.parse::<Ipv4Addr>().unwrap();
    let protocol =
        TracerouteProtocol::from_str(&options.protocol.unwrap_or_else(|| "udp".to_string()));
    let pmtud_mutex = Arc::new(Mutex::new(options.pmtud));

    let semaphore = Arc::new(Semaphore::new(4));
    let ttl_mutex = Arc::new(Mutex::new(0u8));
    let mtu_mutex = Arc::new(Mutex::new(65535));

    let mut recv_buf = [0u8; 1024];
    let recv_sock =
        Arc::new(RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()).unwrap());

    let mut tasks = vec![];

    let data = Arc::new(Mutex::new(HashMap::new()));

    for _ in 0..255 {
        let target = target.clone();
        let semaphore = Arc::clone(&semaphore);
        let counter_mutex = Arc::clone(&ttl_mutex);
        let mtu_mutex = Arc::clone(&mtu_mutex);
        let pmtud_mutex = Arc::clone(&pmtud_mutex);
        let recv_sock = Arc::clone(&recv_sock);
        let data = Arc::clone(&data);

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
                    let guard = pmtud_mutex.lock().await;

                    *guard
                };

                let mtu: Option<u16> = if path_maximum_transmission_unit_discovery {
                    Some(
                        path_mtu_discovery(
                            &target,
                            Arc::clone(&mtu_mutex),
                            ttl,
                            Arc::clone(&pmtud_mutex),
                        )
                        .await,
                    )
                } else {
                    None
                };

                let (_bytes_received, ip_addr) = recv_sock.recv_from(&mut recv_buf).await.unwrap();

                let icmp_packet = IcmpPacket::new(&recv_buf[IP_HDR_LEN..]).unwrap();

                let reverse_dns_task = tokio::task::spawn_blocking(move || {
                    dns_lookup::lookup_addr(&ip_addr.clone().ip()).unwrap()
                });
                let hostname = reverse_dns_task.await.unwrap();

                match icmp_packet.get_icmp_type() {
                    IcmpTypes::TimeExceeded => {
                        /* A part of the original IPv4 packet (header + at least first 8 bytes)
                         * is contained in an ICMP error message. We use the identification field
                         * to map responses back to correct hops.
                         */
                        let original_ipv4_packet =
                            Ipv4Packet::new(&recv_buf[IP_HDR_LEN + ICMP_HDR_LEN..]).unwrap();

                        let hop = original_ipv4_packet.get_identification();

                        let mut data = data.lock().await;
                        data.insert(hop, (ip_addr, hostname, mtu));

                        /* Allow one more task to go through.  */
                        semaphore.add_permits(1);
                    }
                    IcmpTypes::EchoReply => {
                        let mut data = data.lock().await;
                        data.insert(255, (ip_addr, hostname, mtu));

                        semaphore.close();
                    }
                    _ => {}
                }

                permit.forget();
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    let data = data.lock().await;

    for (i, hop) in data.keys().sorted().enumerate() {
        let (ip_addr, hostname, mtu) = data.get(hop).unwrap();
        
        /* Print hop, hostname, and ip_addr.  */
        print!("hop: {} - {} ({:?})", i + 1, hostname, ip_addr);
        
        if mtu.is_none() {
            /* We have no MTU information for this hop, so print a line feed.  */
            print!("\n");
        } else {
            /* We have MTU information for this hop. */
            if let Some(previous_hop) = data.get(&(hop-1)) {
                /* If we have MTU information for previous hop...  */
                if let Some(previous_mtu) = previous_hop.2 {
                    /* If previous MTU is the same as current, print a line feed,
                     * otherwise, print MTU information as well.
                     */
                    if previous_mtu == mtu.unwrap() {
                        print!("\n")
                    } else {
                        print!(" - pmtu: {}\n", mtu.unwrap());
                    }
                }
            } else {
                /* We don't have MTU information for this hop.  */
                print!(" - pmtu: {}\n", mtu.unwrap());
            }
        }
    }

    Ok(())
}

async fn trace_udp(target: &Ipv4Addr, ttl: u8) {
    let sock = UdpSocket::bind("192.168.1.64:8000").await.unwrap();

    sock.set_ttl(u32::from(ttl)).unwrap();
    sock.send_to(&[], (*target, 33434)).await.unwrap();
}

async fn trace_icmp(target: &Ipv4Addr, ttl: u8) {
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::from(255).into()).unwrap();

    let mut ipv4_buf = [0u8; IP_HDR_LEN + ICMP_HDR_LEN];
    let mut icmp_buf = [0u8; ICMP_HDR_LEN];
    let mut ipv4_packet = build_ipv4_packet(
        &mut ipv4_buf,
        *target,
        (IP_HDR_LEN + ICMP_HDR_LEN) as u16,
        ttl,
    );
    let icmp_packet = build_icmp_packet(&mut icmp_buf);

    ipv4_packet.set_payload(&icmp_packet.packet());

    sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &(1i32))
        .unwrap();
    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &i32::from(ttl))
        .unwrap();
    sock.send_to(ipv4_packet.packet(), (*target, 0))
        .await
        .unwrap();
}

async fn path_mtu_discovery(
    target: &Ipv4Addr,
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
    let ipv4_packet = build_ipv4_packet(&mut buf, *target, *mtu, ttl);

    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &(i32::from(ttl) + 1))
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

fn build_ipv4_packet(buf: &mut [u8], dest: Ipv4Addr, size: u16, ttl: u8) -> MutableIpv4Packet {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Flags;

    let mut packet = MutableIpv4Packet::new(buf).unwrap();
    packet.set_version(4);
    packet.set_ttl(ttl);
    packet.set_header_length(5);  /* In bytes.  */

    /* We are setting the identification field to the TTL 
     * that we later use to map responses back to correct hops
     */
    packet.set_identification(ttl as u16);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    packet.set_source("192.168.1.64".parse::<Ipv4Addr>().unwrap());
    packet.set_destination(dest);
    packet.set_flags(Ipv4Flags::DontFragment);
    packet.set_total_length(size);
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
