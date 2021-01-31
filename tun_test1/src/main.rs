use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use tokio::io::AsyncReadExt;
use tokio_tun::result::Result;
use tokio_tun::TunBuilder;


#[tokio::main]
async fn main() -> Result<()> {
    let tun = TunBuilder::new()
        .name("gusa")            // if name is empty, then it is set by kernel.
        .tap(false)          // false (default): TUN, true: TAP.
        .packet_info(false)  // false: IFF_NO_PI, default is true.
        .up()                // or set it up manually using `sudo ip link set <tun-name> up`.
        .try_build()?;       // or `.try_build_mq(queues)` for multi-queue support.

    println!("tun created, name: {}, fd: {}", tun.name(), tun.as_raw_fd());

    let (mut reader, mut _writer) = tokio::io::split(tun);

    let mut buf = [0u8; 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        println!("reading {} bytes: {:?}", n, &buf[..n]);
    }
}
