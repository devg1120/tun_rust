

use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use tokio::io::AsyncReadExt;
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

use tokio_tun::Tun;
use tokio::io::WriteHalf;
use tokio::io::AsyncWriteExt;

mod packet_handler;

/*
fn capture_packet(packet: &EthernetPacket) {
  //　イーサネットの上位のプロトコルを確認
  match packet.get_ethertype() {
    // Ipv4上のtcpまたはudpを表示
    EtherTypes::Ipv4 => {
      let ipv4 = Ipv4Packet::new(packet.payload());
      if let Some(ipv4) = ipv4 {
        match ipv4.get_next_level_protocol() {
          IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(ipv4.payload());
            if let Some(tcp) = tcp {
              println!("TCP {}:{} -> {}:{}", ipv4.get_source(), tcp.get_source(), ipv4.get_destination(), tcp.get_destination());
            }
          }
          IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(ipv4.payload());
            if let Some(udp) = udp {
              println!("UDP {}:{} -> {}:{}", ipv4.get_source(), udp.get_source(), ipv4.get_destination(), udp.get_destination());
            }
          }
          _ => println!("not tcp"),
        }
      }
    }
    EtherTypes::Ipv6 => {
         println!("pv6")
    }
    EtherTypes::Arp => {
         println!("arp")
    }
    _ => println!("unknown packet"),
  }
}
*/

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

    let (mut reader, mut writer) = tokio::io::split(tun);

    let mut buf = [0u8; 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        let r = writer.write(&buf);
        //println!("{:?}",r);

        //println!("reading {} bytes: {:?}", n, &buf[..n]);
        //let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..n]).unwrap();
        
        //let fake_ethernet_frame = EthernetPacket::new(&mut buf[..n]).unwrap();
        //capture_packet(&fake_ethernet_frame);
        //
        let header = Ipv4Packet::new(&mut buf[..n]).unwrap(); 
         println!("{} -> {}",header.get_source(), header.get_destination());
         let ihl = usize::from(header.get_header_length());
         let hlen = if ihl > 5  {
                      20 + (ihl - 5)*4
                    }else {
                        20
                    };

        packet_handler::handle_transport_protocol(
            "test",
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header. get_next_level_protocol(),
            //&buf[20..n],
            &buf[hlen..n],
            &mut writer,
        );

        //if let Some(header) = header {
        //                 //                   println!("{?}",header.get_source());
        //                                    //header.get_destination()
        //     println!("Ipv4")
        // } else {
        //                  //println!("[{}]: Malformed IPv4 Packet", interface_name);
        //     println!("unknow")
        // }
    }
}
