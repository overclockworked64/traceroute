use raw_socket::tokio::RawSocket;
use raw_socket::{Domain, Protocol, Type};
use std::{
    env::args,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::{Mutex, Semaphore};
use tokio::net::UdpSocket;


#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let target = args().nth(1).unwrap();

    let mut tasks = vec![];
    let recv_task = tokio::spawn(receiver(target.clone()));

    let semaphore = Arc::new(Semaphore::new(8));

    let counter_mutex = Arc::new(Mutex::new(0));

    for task in 0..255 {
        let _target = target.clone();
        let semaphore = Arc::clone(&semaphore);
        let counter_mutex = Arc::clone(&counter_mutex);

        tasks.push(tokio::spawn(async move {
            if let Ok(permit) = semaphore.clone().acquire_owned().await {
                let sock = UdpSocket::bind(format!("192.168.1.64:{}", 8000 + task)).await.unwrap();
                let mut counter = counter_mutex.lock().await;

                *counter += 1;

                sock.set_ttl(*counter as u32).unwrap();
                sock.send_to(&[], (_target, 33434)).await.unwrap();

                drop(permit);

                if (task + 1) % 8 == 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;    
                }
            }
        }));
    }

    if let Ok(_) = recv_task.await {
        semaphore.close();
    }    

    Ok(())
}

async fn receiver(target: String) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 1024];
    let sock = RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()).unwrap();

    sock.bind((Ipv4Addr::new(192, 168, 1, 64), 33434)).await?;

    loop {
        let (_len, addr) = sock.recv_from(&mut buf).await?;

        println!("{:?}", addr);

        if addr.ip() == format!("{}:0", target).parse::<SocketAddr>().unwrap().ip() {
            break;
        }
    }

    Ok(())
}
