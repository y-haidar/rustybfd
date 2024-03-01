use futures::ready;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AsyncRawSocket {
  inner: AsyncFd<i32>,
}

impl AsyncRawSocket {
  // This method must be called in the context of a tokio runtime.
  pub fn new(ifindex: i32) -> Result<Self, ()> {
    let socket_raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_IP) };

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
        &pf as *const _ as *const _,
        std::mem::size_of::<libc::sock_fprog>() as u32,
      )
    } == -1
    {
      let errno = unsafe { libc::__errno_location().read() };
      println!("errno for setsockopt: {errno}");
      return Err(());
    };

    if unsafe {
      libc::fcntl(
        socket_raw,
        libc::F_SETFL,
        libc::fcntl(socket_raw, libc::F_GETFL, 0) | libc::O_NONBLOCK,
      )
    } == -1
    {
      let errno = unsafe { libc::__errno_location().read() };
      println!("errno for setsockopt: {errno}");
      return Err(());
    }

    let mut sadr_ll = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
    sadr_ll.sll_family = libc::AF_PACKET as u16;
    sadr_ll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sadr_ll.sll_ifindex = ifindex;
    if unsafe {
      libc::bind(
        socket_raw,
        &sadr_ll as *const _ as *const _,
        std::mem::size_of::<libc::sockaddr_ll>() as u32,
      )
    } == -1
    {
      let errno = unsafe { libc::__errno_location().read() };
      println!("errno for bind: {errno}");
      return Err(());
    }
    Ok(Self {
      inner: AsyncFd::new(socket_raw).unwrap(),
    })
  }

  // pub async fn read(&self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
  //   loop {
  //     let mut guard = self.inner.readable().await?;
  //     match guard.try_io(|inner| _read(*inner.get_ref(), buf)) {
  //       Ok(result) => return result.map(|v| v.try_into().unwrap()),
  //       Err(_would_block) => continue,
  //     }
  //   }
  // }

  // pub async fn write(&self, buf: &[u8]) -> Result<usize, std::io::Error> {
  //   loop {
  //     let mut guard = self.inner.writable().await?;
  //     match guard.try_io(|inner| _write(*inner.get_ref(), buf)) {
  //       Ok(result) => return result,
  //       Err(_would_block) => continue,
  //     }
  //   }
  // }
}

// TODO: Use custom error

impl AsyncRead for AsyncRawSocket {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    loop {
      let mut guard = ready!(self.inner.poll_read_ready(cx))?;
      let unfilled = buf.initialize_unfilled();
      match guard.try_io(|inner| _read(*inner.get_ref(), unfilled)) {
        Ok(Ok(len)) => {
          buf.advance(len);
          return Poll::Ready(Ok(()));
        }
        Ok(Err(err)) => return Poll::Ready(Err(err)),
        Err(_would_block) => continue,
      }
    }
  }
}

impl AsyncWrite for AsyncRawSocket {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    loop {
      let mut guard = ready!(self.inner.poll_write_ready(cx))?;
      match guard.try_io(|inner| _write(*inner.get_ref(), buf)) {
        Ok(result) => return Poll::Ready(result),
        Err(_would_block) => continue,
      }
    }
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    // flush is a no-op
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    // shutdown is a no-op
    Poll::Ready(Ok(()))
  }
}

fn _read(socket: i32, buf: &mut [u8]) -> Result<usize, std::io::Error> {
  let mut msg_iov = [libc::iovec {
    iov_base: buf.as_mut_ptr() as *mut _,
    iov_len: buf.len(),
  }];
  let mut msg_h = unsafe { std::mem::zeroed::<libc::msghdr>() };
  msg_h.msg_iov = msg_iov.as_mut_ptr();
  msg_h.msg_iovlen = msg_iov.len();
  // let mut sadr_ll = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
  // msg_h.msg_name = &mut sadr_ll as *mut _ as *mut _;
  // msg_h.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as u32;

  let mlen = unsafe { libc::recvmsg(socket, &mut msg_h as *mut _, 0) };
  if mlen == -1 {
    let errno = unsafe { libc::__errno_location().read() };
    // println!("errno: {errno}");
    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
      return Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "TODO: FIXME",
      ));
    }
    return Err(std::io::Error::new(
      std::io::ErrorKind::Other,
      "TODO: FIXME",
    ));
  }
  Ok(mlen.try_into().unwrap())
}

fn _write(socket: i32, buf: &[u8]) -> Result<usize, std::io::Error> {
  let mlen = unsafe { libc::sendmsg(socket, buf as *const _ as *const _, 0) };
  if mlen == -1 {
    let errno = unsafe { libc::__errno_location().read() };
    // println!("errno: {errno}");
    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
      return Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "TODO: FIXME",
      ));
    }
    return Err(std::io::Error::new(
      std::io::ErrorKind::Other,
      "TODO: FIXME",
    ));
  }
  Ok(mlen.try_into().unwrap())
}
