use nix::sys::socket::setsockopt;
use std::{
  collections::HashMap,
  io,
  net::{IpAddr, SocketAddr},
  sync::Arc,
  time::Duration,
};
use tokio::net::UdpSocket;

use crate::{
  packet::{AuthHeader, AuthTypeDiscriminants, CtrlPacket, MAX_CTRL_PKT_SIZE},
  task::{
    add_jitter,
    timer_ctx::{TimerCtx, TimerCtxTrait},
  },
};

use super::auth::check;

// TODO: derive serde, to load from config
pub struct PeerCfg {
  addr: SocketAddr,
  id: u32,
  des_min_tx_int: u32,
  req_min_rx_int: u32, // lowest rate of rx supported
  // req_min_echo_rx_int
  detect_mult: u8,
  auth_type: AuthTypeDiscriminants,
}
impl PeerCfg {
  #[inline]
  pub fn new(
    addr: SocketAddr,
    id: u32,
    detect_mult: u8,
    des_min_tx_int: u32,
    req_min_rx_int: u32,
    auth_type: AuthTypeDiscriminants,
  ) -> Self {
    Self {
      addr,
      id,
      detect_mult,
      des_min_tx_int,
      req_min_rx_int,
      auth_type,
    }
  }

  #[inline]
  fn from_pkt(addr: SocketAddr, pkt: &CtrlPacket, auth_header: &AuthHeader) -> Self {
    Self {
      addr,
      id: pkt.snd_id_from_be(),
      detect_mult: pkt.detect_mult,
      des_min_tx_int: pkt.des_min_tx_int_from_be(),
      req_min_rx_int: pkt.req_min_echo_rx_int_from_be(),
      // TODO: Check if auth_type can be diffrent between local and remote
      // TODO: check if valid auth_type
      auth_type: auth_header.get_auth_type_discriminants(),
    }
  }
  // fn from_???() {
  // // TODO: a `fn` that create new struct from config or when operator change local config
  // }
}
// struct PeerSession {
//   // Just create a new socket on port 0 when needed for now
//   // peer_send_tx: mpsc::Sender<BytesMut>,
//   // peer_send_sock: UdpSocket,

// }
// impl PeerSession {
//   fn new(l_ip: IpAddr) {
//     let l_sock_addr = SocketAddr::new(l_ip, 0);
//     todo!()
//   }
// }

pub trait NotifyBfdSessionDown {
  // TODO:
}
impl NotifyBfdSessionDown for () {}

// the way this is designed, when an update to config from either
// local config or remote config, a whole new struct is made
// TODO: maybe look into improving this later
struct PeerCtrlPktSendTimer {
  local_cfg: Arc<PeerCfg>,
  remote_cfg: Arc<Option<PeerCfg>>,
}
struct PeerCtrlPktRecvTimer<Notif> {
  local_cfg: Arc<PeerCfg>,
  remote_cfg: Arc<Option<PeerCfg>>,
  notify_service: Arc<Notif>,
}

struct PeerSession<Notif> {
  local_cfg: Arc<PeerCfg>,
  remote_cfg: Arc<Option<PeerCfg>>,
  send_timer: TimerCtx<PeerCtrlPktSendTimer>,
  recv_timer: Option<TimerCtx<PeerCtrlPktRecvTimer<Notif>>>,
}

#[async_trait::async_trait]
impl TimerCtxTrait for PeerCtrlPktSendTimer {
  #[inline]
  async fn callback(&self) {
    // todo!()
  }
  #[inline]
  fn duration(&self) -> Duration {
    // Look at FRR's `bs_final_handler`
    if let Some(remote_cfg) = self.remote_cfg.as_ref() {
      if self.local_cfg.des_min_tx_int > remote_cfg.req_min_rx_int {
        return add_jitter(
          Duration::from_micros(self.local_cfg.des_min_tx_int as u64),
          self.local_cfg.detect_mult,
        );
      } else {
        return add_jitter(
          Duration::from_micros(remote_cfg.req_min_rx_int as u64),
          self.local_cfg.detect_mult,
        );
      }
    }
    add_jitter(
      Duration::from_micros(self.local_cfg.des_min_tx_int as u64),
      self.local_cfg.detect_mult,
    )
  }
}
#[async_trait::async_trait]
impl<Notif: NotifyBfdSessionDown + Send + Sync> TimerCtxTrait for PeerCtrlPktRecvTimer<Notif> {
  #[inline]
  async fn callback(&self) {
    // TODO: send the appropriate ctrlpkt for session down
    // self.0

    // TODO: send a msg downstream(design a trait; provide an example RPC implementation of the trait)
    // self.1
  }
  #[inline]
  /// the timer duration is going to be `jittered(detect_mult * des_min_tx_int)`
  fn duration(&self) -> Duration {
    // look at FRR's `bfd_recv_cb`
    if let Some(remote_cfg) = self.remote_cfg.as_ref() {
      if self.local_cfg.req_min_rx_int > remote_cfg.des_min_tx_int {
        return Duration::from_micros(
          remote_cfg.detect_mult as u64 * self.local_cfg.req_min_rx_int as u64,
        );
      } else {
        return Duration::from_micros(
          remote_cfg.detect_mult as u64 * remote_cfg.des_min_tx_int as u64,
        );
      }
    }
    todo!()
  }
}

pub struct Bfd<Notif> {
  l_sock_addr: SocketAddr,
  // sock: UdpSocket,
  // TODO: passive mode
  // TODO: demand mode?
  timers: HashMap<IpAddr, PeerSession<Notif>>,
}
impl<Notif: NotifyBfdSessionDown + Send + Sync + 'static> Bfd<Notif> {
  pub async fn serve(l_sock_addr: SocketAddr, peers: Vec<PeerCfg>, _notify_service: Arc<Notif>) {
    let timers = peers
      .into_iter()
      .map(|p| {
        let addr = p.addr.ip();
        let p = Arc::new(p);
        let rp = Arc::new(None);
        (
          addr,
          PeerSession {
            local_cfg: p.clone(),
            remote_cfg: rp.clone(),
            send_timer: TimerCtx::new(PeerCtrlPktSendTimer {
              local_cfg: p.clone(),
              remote_cfg: rp.clone(),
            }),
            recv_timer: None,
          },
        )
      })
      .collect();
    // let sock = UdpSocket::bind(l_sock_addr).await?;

    Self {
      l_sock_addr,
      timers,
    }
    ._serve()
    .await
    .unwrap();
  }

  async fn _serve(self) -> io::Result<()> {
    let sock = UdpSocket::bind(self.l_sock_addr).await?;
    // TODO: add mhop support
    // TODO: check if this ttl value is correct for shop
    // setsockopt(&sock, nix::sys::socket::sockopt::Ipv4Ttl, &1).unwrap();
    // setsockopt(&sock, nix::sys::socket::sockopt::Ipv6Ttl, &1).unwrap();

    let mut buf = [0; MAX_CTRL_PKT_SIZE * 1];
    // let mut buf = bytes::BytesMut::zeroed(MAX_CTRL_PKT_SIZE * 2);
    loop {
      let (len, addr) = sock.recv_from(buf.as_mut()).await?;
      if len == 0 {
        tracing::trace!(
          "recv_from returned zero length; I think this happens when pkt is bigger than buf"
        );
        continue;
      }

      if !self.timers.contains_key(&addr.ip()) {
        tracing::trace!("received from unknown address: {addr}");
        continue;
      }

      let pkt = CtrlPacket::read_bytes(len, &buf).unwrap();
      if !check(
        len,
        pkt,
        &buf,
        AuthTypeDiscriminants::from_repr(2).unwrap(),
        &b"some_random_key".to_vec(),
      ) {
        continue;
      }

      // println!("{:?}", pkt);
      // let auth_head = pkt.get_auth_header(&buf).unwrap();
      // println!("{:?}", auth_head);
      // let auth_type = auth_head.get_auth_type(&buf);
      // println!("{:?}", auth_type);
      // println!("{:?} bytes received from {:?}", len, addr);
      // OUTPUT, recv from cisco router:
      // CtrlPacket { ver_and_diag: VerDiag { version: 1, diagnostic: Some(NoDiagnostic) }, state_and_flags: StateFlags { state: Down, flags: F_AUTH_PRESENT }, detect_mult: 3, length: 48, snd_id: 1, rcv_id: 0, des_min_tx_int: 1000000, req_min_rx_int: 1000000, req_min_echo_rx_int: 0 }
      // AuthHeader { typ: 2, lenth: 24, key_id: 1, __reserved_part_of_pass: 0 }
      // Md5(AuthMd5 { seq: 0, digest: [15, a8, 06, 20, 95, d7, a2, 3d, b2, 43, 5e, 22, 79, 1a, 28, a4] })
      // 48 bytes received from 172.30.135.1:49152

      // tx.send((buf[..len].to_vec(), addr)).await.unwrap();
      // tokio::spawn(async move { peer_serve(addr).await });
    }
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
