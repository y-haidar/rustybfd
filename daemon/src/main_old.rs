use std::{net::Ipv4Addr, ptr::null_mut, str::FromStr};

use libc::{c_void, iovec, msghdr, IPTOS_PREC_INTERNETCONTROL, IPVERSION};
use network_types::{
    bitfield::BitfieldUnit,
    eth::EthHdr,
    ip::{IpHdr, Ipv4Hdr},
    udp::UdpHdr,
};

// struct MyData([u8; 8]);

#[repr(C)]
struct MyPacket<const S: usize> {
    eth_h: EthHdr,
    ip_h: IpHdr,
    udp_h: UdpHdr,
    payload: [u8; S],
}

fn main() {
    let mut total_len = 0u16;
    let eth_h = EthHdr {
        dst_addr: [0x44, 0xa5, 0x6e, 0x00, 0x21, 0xb9], // arp
        src_addr: [0x50, 0xeb, 0x71, 0x66, 0x11, 0x74], // ip link show
        ether_type: network_types::eth::EtherType::Ipv4,
    };
    total_len += EthHdr::LEN as u16;
    let addr = Ipv4Addr::from_str("192.168.1.71").unwrap(); // ip addr show
    let mut ip_h = Ipv4Hdr {
        _bitfield_align_1: [],
        _bitfield_1: BitfieldUnit::new([0]),
        tos: IPTOS_PREC_INTERNETCONTROL,
        // will update at the end
        tot_len: 0,
        // assign a random value like frr?
        id: 0,
        frag_off: 0,
        ttl: 255,
        proto: network_types::ip::IpProto::Udp,
        // will update at the end
        check: 0,
        src_addr: addr.into(),
        dst_addr: addr.into(),
    };
    // in FRR this is 6, but here it is 5, not sure if this is a problem.
    // this is because the sizeof in C returns 24, but here 20
    ip_h.set_ihl((Ipv4Hdr::LEN >> 2) as u8);
    ip_h.set_version(IPVERSION);
    total_len += Ipv4Hdr::LEN as u16;
    // total_len += 4; // to match with FRR?

    let udp_h = UdpHdr {
        source: 8088u16.to_be(),
        dest: 8088u16.to_be(),
        // will update at the end
        len: 0,
        // will update at the end
        check: 0,
    };
    let payload = *b"Hello World";
    total_len += payload.len() as u16;

    udp_h.len = (total_len - EthHdr::LEN as u16 - Ipv4Hdr::LEN as u16).to_be();
    // uh->check = bfd_pkt_checksum(
    // 	uh, (total_len - sizeof(struct iphdr) - sizeof(struct ethhdr)),
    // 	(struct in6_addr *)&iph->saddr, AF_INET);

    ip_h.tot_len = (total_len - EthHdr::LEN as u16).to_be();
    // iph->check = in_cksum((const void *)iph, sizeof(struct iphdr));

    let mut packet = MyPacket {
        eth_h,
        ip_h: IpHdr::V4(ip_h),
        udp_h,
        payload,
    };
    let packet_ptr: *mut c_void = &mut packet as *mut _ as *mut c_void;
    let mut msg_iov = iovec {
        iov_base: packet_ptr,
        iov_len: 0,
    };

    let msg_h = msghdr {
        msg_name: todo!(),
        msg_namelen: todo!(),
        msg_iov: &mut msg_iov as *mut _,
        msg_iovlen: total_len,
        msg_control: null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
}
