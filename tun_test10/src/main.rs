use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_tun::result::Result;
use tokio_tun::Tun;
use tokio_tun::TunBuilder;
//use tokio::spawn;
//use tokio::task;

use pnet::packet::ipv4::Ipv4Packet;
use std::net::IpAddr;

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod packet_handler;
mod server;

#[derive(Debug)]
pub struct Target {
    ip: IpAddr,
    age: u8,
    tx: mpsc::Sender<Command>,
    //rx: mpsc::Receiver<Command>,
}
/*
#[derive(Debug)]
enum Command {
    Get {
        key: String,
    },
    Set {
        key: String,
        val: Vec<u8>,
    }
}
*/
#[derive(Debug)]
pub enum Command {
    Get {
        key: String,
    },
    Set {
        key: String,
        source: IpAddr,
        dest: IpAddr,
        proto: pnet::packet::ip::IpNextHeaderProtocol,
        val: Vec<u8>,
    },
    Cmd {
        key: String,
    },
}

fn replyer_spawn(
    mut _writer: tokio::io::WriteHalf<Tun>,
    mut rx1: mpsc::Receiver<Command>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(cmd) = rx1.recv().await {
            use Command::*;

            match cmd {
                Get { key } => {
                    println!("    Get");
                }
                Set { key, source, dest, proto, val } => {
                    println!("    Set");
                    async {
                        _writer.write(&val[..]).await;
                    }
                    .await;
                }
                Cmd { key } => {
                    println!("    Cmd");
                }
            }
        }
    })
}

fn target_spawn(
    ipaddr: IpAddr,
    mut tx1: mpsc::Sender<Command>,
    mut rx1: mpsc::Receiver<Command>,
) -> tokio::task::JoinHandle<()> {
    let mut cnt = 0;

    tokio::spawn(async move {
        while let Some(cmd) = rx1.recv().await {
            use Command::*;
            match cmd {
                Get { key } => {
                    println!("  Get->");
                }
                Set { key, source, dest, proto, val } => {
                    cnt = cnt + 1;

                    let packet_vec = packet_handler::make_handle_transport_protocol(
                        "test",
                        source,
                        dest,
                        proto,
                        &val[..],
                    );

                    match packet_vec {
                        Some(v) => {
                            println!(" [{}] {} Set->", cnt, ipaddr.to_string());
                            let cmd2 = Command::Set {
                                key: key,
                                source: dest,
                                dest: source,
                                proto: proto,
                                val: v,
                            };
                            async {
                                tx1.send(cmd2).await;
                            }
                            .await;
                        }
                        None => {
                            println!("none value");
                        }
                    };
                }
                Cmd { key } => {
                    println!("  Cmd-> {}", key);
                }
            }
        }
    })
}

//------------------------------------------------------
async fn start(arc_map: &Arc<std::sync::Mutex<HashMap<IpAddr, Target>>> ) -> Result<()> {
    let tun = TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
        .mtu(1500)
        .up()
        .address(Ipv4Addr::new(10, 0, 0, 1))
        .destination(Ipv4Addr::new(10, 1, 0, 1))
        .broadcast(Ipv4Addr::BROADCAST)
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .try_build()?;

    println!("-----------");
    println!("tun created");
    println!("-----------");

    println!(
        "┌ name: {}\n├ fd: {}\n├ mtu: {}\n├ flags: {}\n├ address: {}\n├ destination: {}\n├ broadcast: {}\n└ netmask: {}",
        tun.name(),
        tun.as_raw_fd(),
        tun.mtu().unwrap(),
        tun.flags().unwrap(),
        tun.address().unwrap(),
        tun.destination().unwrap(),
        tun.broadcast().unwrap(),
        tun.netmask().unwrap(),
    );

    println!("---------------------");
    println!("ping 10.1.0.2 to test");
    println!("---------------------");

    let (mut reader, mut _writer) = tokio::io::split(tun);

    //------------------------------------------------
    let (rep_tx, mut rep_rx) = mpsc::channel(1);
    let rep_tx_ = rep_tx.clone();

    let _replyer = replyer_spawn(_writer, rep_rx);

    //----------------------------------------------
    let mut buf = [0u8; 1024];
    //let mut map: HashMap<IpAddr, Target> = HashMap::new();

    loop {
        let n = reader.read(&mut buf).await?;

        let header = Ipv4Packet::new(&mut buf[..n]).unwrap();
        println!("{} -> {}", header.get_source(), header.get_destination());
        let ihl = usize::from(header.get_header_length());
        let hlen = if ihl > 5 { 20 + (ihl - 5) * 4 } else { 20 };

        let ipaddr = IpAddr::V4(header.get_destination());

        let mut map = arc_map.lock().unwrap();
        //let map2 = Arc::clone(&arc_map);
        //let map = map2.lock().unwrap();
        let tar_tx_ = if map.contains_key(&ipaddr) {
            match map.get(&ipaddr) {
                Some(target) => &target.tx,
                None => {
                    println!(" is unreviewed.");
                    continue;
                }
            }
        } else {
            let (tar_tx, mut tar_rx) = mpsc::channel(1);
            let tar_tx_ = tar_tx.clone();
            let _target = target_spawn(ipaddr, rep_tx_.clone(), tar_rx);
            //map.insert(ipaddr, Target { ip: ipaddr, age: 1, tx: tar_tx_ });
            //let map = arc_map.lock().unwrap();
            map.insert(ipaddr, Target { ip: ipaddr, age: 1, tx: tar_tx_ });
            match map.get(&ipaddr) {
                Some(target) => &target.tx,
                None => {
                    println!(" is unreviewed.");
                    continue;
                }
            }
        };

        let cmd = Command::Set {
            key: "foo".to_string(),
            source: IpAddr::V4(header.get_source()),
            dest: IpAddr::V4(header.get_destination()),
            proto: header.get_next_level_protocol(),
            val: (&buf[hlen..n]).to_vec(),
        };

        tar_tx_.send(cmd).await.unwrap();

        //let cmd2 = Command::Cmd {
        //    key: "foo2".to_string(),
        //};
        //tar_tx_.send(cmd2).await.unwrap();
    }
}

//---------------------------------------------------
fn main() -> Result<()> {
    let mut rt = tokio::runtime::Runtime::new()?;
    let mut map: HashMap<IpAddr, Target> = HashMap::new();
    let arc_map = Arc::new(Mutex::new(map));

    let arc_map1 = Arc::clone(&arc_map);
    let arc_map2 = Arc::clone(&arc_map);

    rt.block_on(async {
        tokio::spawn( async {
            server::start(arc_map1).await;
        });

        start(&arc_map2).await;

        Ok(())
    })
/*
fn main() -> Result<()> {
    let mut rt = tokio::runtime::Runtime::new()?;
    let mut map: HashMap<IpAddr, Target> = HashMap::new();

    
    rt.block_on(async {
        tokio::spawn(async  {
            server::start().await;
        });

        start(&mut map).await;

        Ok(())
    })
*/
/*
    rt.block_on(async {

        tokio::spawn(async {
            start(&mut map).await;
        });

        //server::start(&map).await;
        server::start().await;

        Ok(())
    })
*/
}
