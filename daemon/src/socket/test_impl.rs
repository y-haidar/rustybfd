use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

use crate::packet::CtrlPacket;

pub async fn serve() -> io::Result<()> {
  let sock = UdpSocket::bind("172.30.135.50:3784".parse::<SocketAddr>().unwrap()).await?;
  let recv = Arc::new(sock);
  // let send = recv.clone();
  // let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

  // tokio::spawn(async move {
  //   while let Some((bytes, addr)) = rx.recv().await {
  //     let len = send.send_to(&bytes, &addr).await.unwrap();
  //     println!("{:?} bytes sent", len);
  //   }
  // });

  // let mut buf = [0; 1024];
  let mut buf = bytes::BytesMut::zeroed(std::mem::size_of::<CtrlPacket>() * 2);
  loop {
    let (len, addr) = recv.recv_from(buf.as_mut()).await?;
    if len == 0 {
      tracing::trace!(
        "recv_from returned zero length; I think this happens when pkt is bigger than buf"
      );
      continue;
    }
    let pkt = CtrlPacket::read_bytes(len, &buf).unwrap();
    println!("{:?}", pkt);
    let auth_head = pkt.get_auth_header(&buf).unwrap();
    println!("{:?}", auth_head);
    let auth_type = auth_head.get_auth_type(&buf);
    println!("{:?}", auth_type);
    println!("{:?} bytes received from {:?}", len, addr);
    // OUTPUT, recv from cisco router:
    // CtrlPacket { ver_and_diag: VerDiag { version: 1, diagnostic: Some(NoDiagnostic) }, state_and_flags: StateFlags { state: Down, flags: F_AUTH_PRESENT }, detect_mult: 3, length: 48, snd_id: 1, rcv_id: 0, des_min_tx_int: 1000000, req_min_rx_int: 1000000, req_min_echo_rx_int: 0 }
    // AuthHeader { typ: 2, lenth: 24, key_id: 1, __reserved_part_of_pass: 0 }
    // Md5(AuthMd5 { seq: 0, digest: [15, a8, 06, 20, 95, d7, a2, 3d, b2, 43, 5e, 22, 79, 1a, 28, a4] })
    // 48 bytes received from 172.30.135.1:49152

    // tx.send((buf[..len].to_vec(), addr)).await.unwrap();
    // tokio::spawn(async move { peer_serve(addr).await });
  }
}

// async fn peer_serve(remote_addr: SocketAddr) -> io::Result<()> {
//   let sock = UdpSocket::bind("172.30.135.50:0".parse::<SocketAddr>().unwrap()).await?;
//   sock.connect(remote_addr).await?;
//   // println!("connected to peer {:?}", remote_addr);
//   let mut buf = [0; 1024];
//   loop {
//     let len = sock.recv(&mut buf).await?;
//     println!("{:?} bytes received from peer {:?}", len, remote_addr);
//   }
// }
