//! A simple echo server.
//!
//! You can test this out by running:
//!
//!     cargo run --example server 127.0.0.1:12345
//!
//! And then in another window run:
//!
//!     cargo run --example client ws://127.0.0.1:12345/

use std::{env };

//use futures_util::StreamExt;
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use std::collections::HashMap; 
//use std::net::IpAddr; 
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::sync::{Arc, Mutex}; 
//use tokio::sync::Mutex;
//use std::sync::Arc;

use std::str::FromStr;


use futures_util::{SinkExt};
use log::*;
use std::{net::SocketAddr, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Error, tungstenite::Message, tungstenite::Result};
//use tungstenite::{Message, Result};

//mod main;

/*
#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = env_logger::try_init();
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8080".to_string());

    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    info!("Listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream));
    }

    Ok(())
}
*/

pub async fn start(arc_map: Arc<std::sync::Mutex<HashMap<IpAddr,super::Target>>>) -> Result<()> {
//pub async fn start() -> Result<(), Error> {
    //let _ = env_logger::try_init();
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8080".to_string());

    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    info!("Listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        let peer = stream.peer_addr().expect("connected streams should have a peer address");
        //tokio::spawn(accept_connection(arc_map.clone(), stream));
        //tokio::spawn(accept_connection(arc_map.clone(), peer, stream));

        //tokio::spawn(handle_connection(arc_map.clone(), peer, stream));
        tokio::spawn(handle_connection(arc_map.clone(), peer, stream));

        //let handle = tokio::spawn(handle_connection(arc_map, peer, stream));

    }

    Ok(())
}


//async fn accept_connection(arc_map: Arc<std::sync::Mutex<HashMap<IpAddr,super::Target>>>,peer: SocketAddr,stream: TcpStream)
//   -> Result<()> {
//    /*
//    let addr = stream.peer_addr().expect("connected streams should have a peer address");
//    //info!("Peer address: {}", addr);
//
//    let ws_stream = tokio_tungstenite::accept_async(stream)
//        .await
//        .expect("Error during the websocket handshake occurred");
//
//    //info!("New WebSocket connection: {}", addr);
//
//    let (write, read) = ws_stream.split();
//    read.forward(write).await.expect("Failed to forward message");
//*/
//
//
////    if let Err(e) = handle_connection(arc_map, peer, stream).await {
////        match e {
////            Error::ConnectionClosed | Error::Protocol(_) | Error::Utf8 => (),
////            err => error!("Error processing connection: {}", err),
////        }
////    }
////    Ok(())
//
///*
//    let ipaddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
//    let mut map = arc_map.lock().unwrap();
//    if map.contains_key(&ipaddr) {
//            match map.get(&ipaddr) {
//                Some(target) => { //&target.tx,
//                                  println!(" is match.");
//                        },
//                None => {
//                    println!(" is unreviewed.");
//                    return;
//                }
//            }
//      }
//*/
//}

/*
//async fn parser(arc_map: &Arc<std::sync::Mutex<HashMap<IpAddr,super::Target>>>, msg :&Message) -> Result<()> {
async fn parser(arc_map: &Arc<std::sync::Mutex<HashMap<IpAddr,super::Target>>>, msg :&Message)  {

   println!("SERVER: MSG");

   let  ipaddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
   //let mut map = arc_map.lock().unwrap();
   let  map = arc_map.lock().unwrap();
        if map.contains_key(&ipaddr) {
 //Box::pin(async move {
            match map.get(&ipaddr) {
                Some(target) => {
                                 //&target.tx,

                          println!("map ok ");
                          //&target.tx,
                          //let cmd = super::Command::Cmd {
                          //    key: "*command".to_string(),
                          //};
                          //let txc = target.tx.clone();
                          //target.tx.send(cmd).await.unwrap();
                          //target.tx.send(cmd);
                          
                          //txc.send(cmd).await.unwrap();
                          //txc.send(cmd).await;
                          //txc.send(cmd);
                        },
                None => {
                          println!("map ng ");
                }
            }
 //});
        }
  //Ok(())

}
*/
/*
async fn parser(arc_map: &Arc<std::sync::Mutex<HashMap<IpAddr,super::Target>>>, msg :&Message) -> Result<()> {

   println!("SERVER: MSG");

   let  ipaddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

   let mut map = arc_map.lock().unwrap();
        if map.contains_key(&ipaddr) {
            match map.get(&ipaddr) {
                Some(target) => {
                                 //&target.tx,
                          println!("map ok ");
                          let cmd = super::Command::Cmd {
                              key: "*command".to_string(),
                          };
                          let txc = target.tx.clone();
                          target.tx.send(cmd).await.unwrap();
                          //target.tx.send(cmd);
                          
                          //txc.send(cmd).await.unwrap();
                          //txc.send(cmd);

                        },
                None => {
                          println!("map ng ");
                }
            }
        };

  Ok(())

}

*/
async fn handle_connection(arc_map: Arc<std::sync::Mutex<HashMap<IpAddr,super::Target>>>,peer: SocketAddr, stream: TcpStream) -> Result<()> {
    let ws_stream = accept_async(stream).await.expect("Failed to accept");
    info!("New WebSocket connection: {}", peer);
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let mut interval = tokio::time::interval(Duration::from_millis(1000));

    // Echo incoming WebSocket messages and send a message periodically every second.

    loop {
        tokio::select! {
            msg = ws_receiver.next() => {
                match msg {
                    Some(msg) => {
                        let msg = msg?;
                        if msg.is_text() ||msg.is_binary() {

                           // parser(&arc_map, &msg).await;

                           ws_sender.send(msg).await?;

                           let rtx_ = {
                                         let  ipaddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

                                         let map = arc_map.lock().unwrap();
                                         //let map_lock = Arc::clone(&arc_map);
                                         //let map = map_lock.lock().unwrap();
                                         let tmp_tx = if map.contains_key(&ipaddr) {
                                                       match map.get(&ipaddr) {
                                                           Some(target) => {
                                                                     println!("map ok ");
                                                                     //Some(target.tx.clone())
                                                                     Some(target.tx.clone())
                                                                   },
                                                           None => {
                                                                     println!("map ng ");
                                                                     None
                                                           }
                                                       }
                                             } else {
                                                  None
                                             };
                                      tmp_tx
                                     }; // arc_map.locked  drop ....
                           
                           match rtx_ {

                               Some(tx) => {
                                             let cmd = super::Command::Cmd {
                                                 key: "*command*".to_string(),
                                             };
                                             tx.send(cmd).await.unwrap();
                                                        println!("tx send ok ");

                                          },
                               None => {
                                      continue;
                                     },

                         };

                        } else if msg.is_close() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = interval.tick() => {
                ws_sender.send(Message::Text("tick".to_owned())).await?;
            }
        }
    }

    Ok(())
}

