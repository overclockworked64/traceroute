use raw_socket::tokio::RawSocket;
use raw_socket::{Domain, Protocol, Type};
use std::{env::args, sync::Arc};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore};

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
    let target = args().nth(1).unwrap();
    let protocol = TracerouteProtocol::from_str(&args().nth(2).unwrap());

    let semaphore = Arc::new(Semaphore::new(4));
    let counter_mutex = Arc::new(Mutex::new(0));

    let mut tasks = vec![];
    let recv_task = tokio::spawn(receiver(Arc::clone(&semaphore)));

    for task in 0..256 {
        let _target = target.clone();
        let semaphore = Arc::clone(&semaphore);
        let counter_mutex = Arc::clone(&counter_mutex);

        tasks.push(tokio::spawn(async move {
            if let Ok(permit) = semaphore.clone().acquire().await {
                let _c = {
                    let mut counter = counter_mutex.lock().await;
                    *counter += 1;
                    *counter
                };

                match protocol {
                    TracerouteProtocol::Udp => {
                        let sock = UdpSocket::bind(format!("192.168.1.64:{}", 8000 + task))
                            .await
                            .unwrap();

                        sock.set_ttl(_c as u32).unwrap();
                        sock.send_to(&[], (_target, 33434)).await.unwrap();
                    }
                    TracerouteProtocol::Icmp => {
                        use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
                        use pnet::packet::icmp::{checksum, IcmpCode, IcmpPacket, IcmpType};
                        use pnet::packet::Packet;
                        use raw_socket::ffi::c_int;
                        use raw_socket::option::{Level, Name};

                        let sock =
                            RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into())
                                .unwrap();

                        let mut buf = [0u8; 8]; // 8: ICMP header length
                        let mut packet = MutableEchoRequestPacket::new(&mut buf).unwrap();

                        packet.set_icmp_type(IcmpType::new(8));
                        packet.set_icmp_code(IcmpCode::new(0));
                        packet.set_sequence_number(_c);
                        packet.set_identifier(0x1337);
                        packet.set_checksum(checksum(&IcmpPacket::new(&packet.packet()).unwrap()));

                        sock.set_sockopt(Level::IPV4, Name::from(2), &(_c as c_int))
                            .unwrap(); // 2: IP_TTL
                        sock.send_to(packet.packet(), (_target, 0)).await.unwrap();
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

async fn receiver(semaphore: Arc<Semaphore>) -> Result<(), std::io::Error> {
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::icmp::IcmpTypes;

    let mut buf = [0u8; 1024];
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()).unwrap();

    loop {
        let (_bytes_received, addr) = sock.recv_from(&mut buf).await?;
        let packet = IcmpPacket::new(&buf[20..]).unwrap();

        println!("{:?}", addr);

        match packet.get_icmp_type() {
            IcmpTypes::TimeExceeded => semaphore.add_permits(1),
            IcmpTypes::EchoReply => break,
            _ => {}
        }
    }

    Ok(())
}
