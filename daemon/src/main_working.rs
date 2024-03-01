use std::{mem, ptr::null_mut};

use etherparse::{Ipv4Dscp, PacketBuilder};
use libc::{
  __errno_location, iovec, msghdr, sendmsg, sockaddr_ll, socket, AF_PACKET, ETH_ALEN, ETH_P_IP,
  IPTOS_PREC_INTERNETCONTROL, SOCK_RAW,
};

// struct MyData([u8; 8]);

fn main() {
  let socket_raw = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_IP) };

  #[rustfmt::skip]
    /* tcpdump -dd udp dst port 3785 ; source FRR: bfdd/bfd_packet.c */
    let mut my_udp_filter = [
      libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 0x0000000c },
      libc::sock_filter { code: 0x15, jt: 0, jf: 8, k: 0x00000800 },
      libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 0x00000017 },
      libc::sock_filter { code: 0x15, jt: 0, jf: 6, k: 0x00000011 },
      libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 0x00000014 },
      libc::sock_filter { code: 0x45, jt: 4, jf: 0, k: 0x00001fff },
      libc::sock_filter { code: 0xb1, jt: 0, jf: 0, k: 0x0000000e },
      libc::sock_filter { code: 0x48, jt: 0, jf: 0, k: 0x00000010 },
      libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 0x00000ec9 },
      libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00040000 },
      libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00000000 },
    ];

  let mut pf = unsafe { std::mem::zeroed::<libc::sock_fprog>() };
  pf.filter = &mut my_udp_filter as *mut _;
  pf.len = my_udp_filter.len() as u16;
  if unsafe {
    libc::setsockopt(
      socket_raw,
      libc::SOL_SOCKET,
      libc::SO_ATTACH_FILTER,
      &mut pf as *mut _ as *mut _,
      mem::size_of::<libc::sock_fprog>() as u32,
    )
  } == -1
  {
    let errno = unsafe { __errno_location().read() };
    println!("errno for setsockopt: {errno}");
  };

  let mut sadr_ll = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
  // sadr.sll_addr = [0, 0, 0x50, 0xeb, 0x71, 0x66, 0x11, 0x74];
  sadr_ll.sll_family = AF_PACKET as u16;
  sadr_ll.sll_protocol = (ETH_P_IP as u16).to_be();
  sadr_ll.sll_ifindex = 3;
  // sadr.sll_halen = ETH_ALEN as u8;
  if unsafe {
    libc::bind(
      socket_raw,
      &sadr_ll as *const _ as *const _,
      mem::size_of::<libc::sockaddr_ll>() as u32,
    )
  } == -1
  {
    let errno = unsafe { __errno_location().read() };
    println!("errno for bind: {errno}");
  }

  {
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

    // println!("{}", unsafe { msg_iov[0].iov_base.add(4).read() as u8 });

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

    // println!("Sending BFD Echo...");
    let isize = unsafe { sendmsg(socket_raw, &msg_h as *const _, 0) };
    println!("Sent: {isize:#?}/{}", packet.len());
  }

  {
    // sleep(Duration::from_secs(1));
    // PacketHeaders::from_ethernet_slice
    // let mut recv_len = None;
    // loop {
    // if errno != libc::EAGAIN || errno != libc::EWOULDBLOCK || errno != libc::EINTR {}
    //     } else {
    //         recv_len = Some(mlen);
    //         break;
    //     }
    // }
    let mut sadr_ll = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
    // sadr_ll.sll_addr = [0, 0, 0x50, 0xeb, 0x71, 0x66, 0x11, 0x74];
    // sadr_ll.sll_family = (ETH_P_IP as u16).to_be(); // THIS IS WRONG
    // sadr_ll.sll_halen = ETH_ALEN as u8;
    // sadr_ll.sll_ifindex = 3;

    let mut msgbuf = [0u8; 53];
    let mut msg_iov = [iovec {
      iov_base: msgbuf.as_mut_ptr() as *mut _,
      iov_len: msgbuf.len(),
    }];

    let mut cmsghdr = unsafe { std::mem::zeroed::<libc::cmsghdr>() };

    let mut msg_h = unsafe { std::mem::zeroed::<msghdr>() };
    msg_h.msg_name = &mut sadr_ll as *mut _ as *mut _;
    msg_h.msg_namelen = mem::size_of::<libc::sockaddr_ll>() as u32;
    msg_h.msg_iov = msg_iov.as_mut_ptr();
    msg_h.msg_iovlen = msg_iov.len();
    msg_h.msg_control = &mut cmsghdr as *mut _ as *mut _;
    msg_h.msg_controllen = mem::size_of::<libc::cmsghdr>();

    // MSG_DONTWAIT
    let mlen = unsafe { libc::recvmsg(socket_raw, &mut msg_h as *mut _, 0) };
    // println!("recv mlen: {mlen:?}");
    if mlen != -1 {
      println!("{:02x?}", msgbuf);
    } else {
      let errno = unsafe { __errno_location().read() };
      println!("errno: {errno}");
    }
  }
  // let socket_std = std::net::UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
  // socket_std.connect(addr).expect("connect function failed");
  // socket_std.send(b"Hello Udp").expect("couldn't send");
  // jh.join().unwrap();
}

// let mut sadr = unsafe { std::mem::zeroed::<libc::sockaddr_in>() };
// sadr.sin_family = (libc::AF_INET as u16).to_be();
// sadr.sin_addr = libc::in_addr {
//     s_addr: Ipv4Addr::from_str("192.168.1.71").unwrap().into(),
// };
// sadr.sin_port = 3785;
