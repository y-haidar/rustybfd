use std::{mem, ptr::null_mut};

use etherparse::{Ipv4Dscp, PacketBuilder};
use libc::{iovec, msghdr, sockaddr_ll, ETH_ALEN, ETH_P_IP, IPTOS_PREC_INTERNETCONTROL};
use rustybfd::AsyncRawSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
  let mut socket = AsyncRawSocket::new(3).unwrap();

  const IP: [u8; 4] = [192, 168, 1, 71];
  const PORT: u16 = 3785;
  let mut ipv4_h = etherparse::Ipv4Header::new(0, 62, etherparse::IpNumber(0), IP, IP).unwrap();
  ipv4_h.dscp = Ipv4Dscp::try_new(IPTOS_PREC_INTERNETCONTROL >> 2).unwrap();
  let builder = PacketBuilder::ethernet2(
    [0x50, 0xeb, 0x71, 0x66, 0x11, 0x74], // ip link show
    [0x44, 0xa5, 0x6e, 0x00, 0x21, 0xb9], // arp
  )
  .ip(etherparse::IpHeaders::Ipv4(ipv4_h, Default::default()))
  // .ipv4(IP, IP, 20)
  .udp(PORT, PORT);

  let payload = *b"Hello World";
  let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
  builder.write(&mut packet, &payload).unwrap();

  // println!("{:02x?}", packet);

  let mut msg_iov = [iovec {
    iov_base: packet.as_mut_ptr() as *mut _,
    iov_len: packet.len(),
  }];

  let mut sadr_ll = sockaddr_ll {
    sll_family: 0,
    sll_protocol: (ETH_P_IP as u16).to_be(),
    sll_ifindex: 3, // ip link show // this is index of `wlp82s0`
    sll_hatype: 0,
    sll_pkttype: 0,
    sll_halen: ETH_ALEN as u8,
    sll_addr: [0, 0, 0x44, 0xa5, 0x6e, 0x00, 0x21, 0xb9], // arp
  };

  let msg_h = msghdr {
    msg_name: &mut sadr_ll as *mut _ as *mut _,
    msg_namelen: mem::size_of::<sockaddr_ll>() as u32,
    msg_iov: msg_iov.as_mut_ptr(),
    msg_iovlen: msg_iov.len(),
    msg_control: null_mut(),
    msg_controllen: 0,
    msg_flags: 0,
  };

  let len = socket
    .write(unsafe { rustybfd::any_as_u8_slice(&msg_h) })
    .await
    .unwrap();
  println!("Sent: {len:#?}/{}", packet.len());

  let mut buf = [0u8; 1000];
  loop {
    let len = socket.read(&mut buf).await.unwrap();
    println!("Got: {len:#?}/{}", packet.len());
    let recv_packet = etherparse::SlicedPacket::from_ethernet(&buf[..len]);
    if let Some(etherparse::TransportSlice::Udp(v)) = recv_packet.unwrap().transport {
      println!("{}", String::from_utf8(v.payload().to_vec()).unwrap());
    }
  }
}
