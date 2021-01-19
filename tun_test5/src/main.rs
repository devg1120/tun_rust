

use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio_tun::result::Result;
use tokio_tun::TunBuilder;

//use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
//use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket };
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;

use std::net::IpAddr;
mod packet_handler;


#[tokio::main]
async fn main() -> Result<()> {
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

    let mut buf = [0u8; 1024];
    loop {
        let n = reader.read(&mut buf).await?;

        //_writer.write_all(&buf).await?;
        //_writer.write(&buf).await?;

        let header = Ipv4Packet::new(&mut buf[..n]).unwrap(); 
         println!("{} -> {}",header.get_source(), header.get_destination());
         let ihl = usize::from(header.get_header_length());
         let hlen = if ihl > 5  {
                      20 + (ihl - 5)*4
                    }else {
                        20
                    };

        //packet_handler::handle_transport_protocol(
        //    "test",
        //    IpAddr::V4(header.get_source()),
        //    IpAddr::V4(header.get_destination()),
        //    header. get_next_level_protocol(),
        //    //&buf[20..n],
        //    &buf[hlen..n],
        //    &buf,
        //    &mut _writer,
        //    //tun,
        //);

        let packet_vec = packet_handler::make_handle_transport_protocol(
            "test",
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header. get_next_level_protocol(),
            //&buf[20..n],
            &buf[hlen..n],
        );

        match packet_vec {
              Some(v) => {
                            _writer.write(&v[..]).await?;
                         },
              None => {
                          println!("none value");
                       },
        };
        //     println!("unknow")
        // }
    }
}
