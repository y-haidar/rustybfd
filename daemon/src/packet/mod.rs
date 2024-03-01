use std::mem::size_of;

use bytemuck::{Pod, Zeroable};
use derivative::Derivative;
use strum_macros::FromRepr;

fn fmt_u32_from_be(f: &u32, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
  let _ = fmt.write_str(&u32::from_be(*f).to_string());
  Ok(())
}
fn fmt_u8_slice_to_hex(f: &[u8], fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
  let _ = fmt.write_fmt(format_args!("{f:02x?}"));
  Ok(())
}

#[derive(Default, Debug, PartialEq, FromRepr)]
#[repr(u8)]
#[non_exhaustive]
pub enum Diagnostic {
  #[default]
  ///   0 -- No Diagnostic
  NoDiagnostic,
  ///   1 -- Control Detection Time Expired
  CtrlDetectionTimeExpired,
  ///   2 -- Echo Function Failed
  EchoFnFailed,
  ///   3 -- Neighbor Signaled Session Down
  NeighborDown,
  ///   4 -- Forwarding Plane Reset
  FpReset,
  ///   5 -- Path Down
  PathDown,
  ///   6 -- Concatenated Path Down
  ConcatPathDown,
  ///   7 -- Administratively Down
  AdminDown,
  ///   8 -- Reverse Concatenated Path Down
  RevConcatPathDown,
  // 9-31 -- Reserved for future use
}
#[derive(Default, PartialEq, Copy, Clone, Zeroable, Pod)]
#[repr(C)]
pub struct VerDiag(u8);
impl VerDiag {
  pub fn get_version(&self) -> u8 {
    self.0 >> 5
  }
  pub fn get_diagnostic(&self) -> Option<Diagnostic> {
    Diagnostic::from_repr(self.0 & 0b00011111u8)
  }
}
#[derive(Default, Debug, PartialEq, FromRepr)]
pub enum State {
  #[default]
  AdminDown,
  Down,
  Init,
  Up,
}
#[derive(Default, PartialEq, Copy, Clone, Zeroable, Pod)]
#[repr(C)]
pub struct StateFlags(u8);
impl StateFlags {
  const F_POLL: u8 = 5;
  const F_FINAL: u8 = 4;
  const F_CPI: u8 = 3;
  const F_AUTH_PRESENT: u8 = 2;
  const F_DEMAND: u8 = 1;
  /// This bit is reserved for future point-to-multipoint extensions to
  /// BFD. It MUST be zero on both transmit and receipt.
  const F_MULTIPOINT: u8 = 0;

  pub fn get_state(&self) -> State {
    State::from_repr((self.0 >> 6) as usize).unwrap()
  }

  pub fn has_poll(&self) -> bool {
    self.0 & (1 << Self::F_POLL) > 0
  }
  pub fn has_final(&self) -> bool {
    self.0 & (1 << Self::F_FINAL) > 0
  }
  pub fn has_cpi(&self) -> bool {
    self.0 & (1 << Self::F_CPI) > 0
  }
  pub fn has_auth_present(&self) -> bool {
    self.0 & (1 << Self::F_AUTH_PRESENT) > 0
  }
  pub fn has_demand(&self) -> bool {
    self.0 & (1 << Self::F_DEMAND) > 0
  }
  pub fn has_multipoint(&self) -> bool {
    self.0 & (1 << Self::F_MULTIPOINT) > 0
  }

  pub fn set_poll(&mut self) {
    self.0 |= 1 << Self::F_POLL;
  }
  pub fn unset_poll(&mut self) {
    self.0 &= 0xff ^ (1 << Self::F_POLL);
  }
  pub fn set_final(&mut self) {
    self.0 |= 1 << Self::F_FINAL;
  }
  pub fn unset_final(&mut self) {
    self.0 &= 0xff ^ (1 << Self::F_FINAL);
  }
  pub fn set_cpi(&mut self) {
    self.0 |= 1 << Self::F_CPI;
  }
  pub fn unset_cpi(&mut self) {
    self.0 &= 0xff ^ (1 << Self::F_CPI);
  }
  pub fn set_auth_present(&mut self) {
    self.0 |= 1 << Self::F_AUTH_PRESENT;
  }
  pub fn unset_auth_present(&mut self) {
    self.0 &= 0xff ^ (1 << Self::F_AUTH_PRESENT);
  }
  pub fn set_demand(&mut self) {
    self.0 |= 1 << Self::F_DEMAND;
  }
  pub fn unset_demand(&mut self) {
    self.0 &= 0xff ^ (1 << Self::F_DEMAND);
  }
  pub fn set_multipoint(&mut self) {
    self.0 |= 1 << Self::F_MULTIPOINT;
  }
  pub fn unset_multipoint(&mut self) {
    self.0 &= 0xff ^ (1 << Self::F_MULTIPOINT);
  }
}

#[derive(Default, Copy, Clone, Zeroable)]
#[repr(C)]
pub struct CtrlPacket {
  pub v_d: VerDiag,    /* Version and diagnostic */
  pub s_f: StateFlags, /* State and flags */
  pub detect_mult: u8,
  pub length: u8,  /* Whole packet length */
  pub snd_id: u32, /* Sender ID, aka 'my discriminator' */
  pub rcv_id: u32, /* Receiver ID, aka 'your discriminator' */
  pub des_min_tx_int: u32,
  pub req_min_rx_int: u32,
  pub req_min_echo_rx_int: u32,

  pub auth_header: AuthHeader,
  pub auth_data: [u8; size_of::<AuthSha1>()],
}
unsafe impl Pod for CtrlPacket {}

#[derive(Debug, Default, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct AuthHeader {
  pub typ: u8,
  pub lenth: u8,
  pub key_id: u8,
  pub __reserved_part_of_pass: u8,
}

#[derive(Debug, Default, Copy, Clone)]
#[repr(C, u8)]
#[non_exhaustive]
pub enum AuthType<'a> {
  #[default]
  NoneReserved,
  // Simple(&'a AuthSimple),
  SimpleNotSupported,
  Md5(&'a AuthMd5),
  MeticulousMd5(&'a AuthMd5),
  Sha1(&'a AuthSha1),
  MeticulousSha1(&'a AuthSha1),
}
impl<'a> AuthType<'a> {
  pub const NONERESERVED: u8 = 0;
  pub const SIMPLE: u8 = 1;
  pub const MD5: u8 = 2;
  pub const METICULOUSMD5: u8 = 3;
  pub const SHA1: u8 = 4;
  pub const METICULOUSSHA1: u8 = 5;
}

// #[derive(Debug, Default, Copy, Clone, Zeroable)]
// #[repr(C)]
// pub struct AuthSimple {
//   pub pass: [u8; 16], // 16 from RFC
// }
// unsafe impl Pod for AuthSimple {}

#[derive(Derivative, Default, Copy, Clone, Zeroable)]
#[derivative(Debug)]
#[repr(C)]
/// Section https://www.rfc-editor.org/rfc/rfc5880#section-4.3
pub struct AuthMd5 {
  // __reserved: u8, // comment this as this creating alignment/padding issues
  #[derivative(Debug(format_with = "fmt_u32_from_be"))]
  /// For Keyed MD5 Authentication, this value is incremented occasionally. For
  /// Meticulous Keyed MD5 Authentication, this value is incremented for
  /// each successive packet transmitted for a session.
  pub seq: u32,
  #[derivative(Debug(format_with = "fmt_u8_slice_to_hex"))]
  /// Auth Key/Digest
  pub digest: [u8; 16], // 24 from RFC but - bytes in AuthHeader
}
unsafe impl Pod for AuthMd5 {}

#[derive(Derivative, Default, Copy, Clone, Zeroable)]
#[derivative(Debug)]
#[repr(C)]
/// Section https://www.rfc-editor.org/rfc/rfc5880#section-4.4
pub struct AuthSha1 {
  // __reserved: u8, // comment this as this creating alignment/padding issues
  #[derivative(Debug(format_with = "fmt_u32_from_be"))]
  /// For Keyed SHA1 Authentication, this value is incremented occasionally. For
  /// Meticulous Keyed SHA1 Authentication, this value is incremented for
  /// each successive packet transmitted for a session.
  pub seq: u32,
  #[derivative(Debug(format_with = "fmt_u8_slice_to_hex"))]
  /// Auth Key/Digest
  pub digest: [u8; 20], // 28 from RFC but - bytes in AuthHeader
}
unsafe impl Pod for AuthSha1 {}

impl std::fmt::Debug for VerDiag {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("VerDiag")
      .field("version", &self.get_version())
      .field("diagnostic", &self.get_diagnostic())
      .finish()
  }
}
impl std::fmt::Debug for StateFlags {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("StateFlags")
      .field("state", &self.get_state())
      .field("flag_poll", &self.has_poll())
      .field("flag_final", &self.has_final())
      .field("flag_cpi", &self.has_cpi())
      .field("flag_auth_present", &self.has_auth_present())
      .field("flag_demand", &self.has_demand())
      .field("flag_multipoint", &self.has_multipoint())
      .finish()
  }
}
impl std::fmt::Debug for CtrlPacket {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let auth_type = match self.auth_header.typ {
      AuthType::NONERESERVED => AuthType::NoneReserved,
      // Not supported. Alignment was annoying and why use plain password anyway
      // AuthType::SIMPLE => AuthType::Simple(bytemuck::from_bytes(
      //   &self.auth_data[..size_of::<AuthSimple>()],
      // )),
      AuthType::MD5 => AuthType::Md5(bytemuck::from_bytes(
        &self.auth_data[..size_of::<AuthMd5>()],
      )),
      AuthType::METICULOUSMD5 => AuthType::Md5(bytemuck::from_bytes(
        &self.auth_data[..size_of::<AuthMd5>()],
      )),
      AuthType::SHA1 => AuthType::Sha1(bytemuck::from_bytes(
        &self.auth_data[..size_of::<AuthSha1>()],
      )),
      AuthType::METICULOUSSHA1 => AuthType::MeticulousSha1(bytemuck::from_bytes(
        &self.auth_data[..size_of::<AuthSha1>()],
      )),
      _ => return Err(std::fmt::Error),
    };

    f.debug_struct("CtrlPacket")
      .field("vdiag", &self.v_d)
      .field("flags", &self.s_f)
      .field("detect_mult", &self.detect_mult)
      .field("length", &self.length)
      .field("snd_id", &u32::from_be(self.snd_id))
      .field("rcv_id", &u32::from_be(self.rcv_id))
      .field(
        "des_min_tx_int",
        &(u32::from_be(self.des_min_tx_int) / 1000),
      )
      .field(
        "req_min_rx_int",
        &(u32::from_be(self.req_min_rx_int) / 1000),
      )
      .field(
        "req_min_echo_rx_int",
        &(u32::from_be(self.req_min_echo_rx_int) / 1000),
      )
      .field("auth_header", &self.auth_header)
      .field("auth_data", &auth_type)
      .finish()
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn test() {
    let mut recv_buff = CtrlPacket::default();

    let sample_pkt_with_md5_auth = &[
      0x20, 0x44, 0x03, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42,
      0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x02, 0x18, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x15, 0xa8, 0x06, 0x20, 0x95, 0xd7, 0xa2, 0x3d, 0xb2, 0x43, 0x5e, 0x22, 0x79,
      0x1a, 0x28, 0xa4,
    ];

    let recv_buff_slice = bytemuck::bytes_of_mut(&mut recv_buff);
    recv_buff_slice[..sample_pkt_with_md5_auth.len()].copy_from_slice(sample_pkt_with_md5_auth);

    insta::assert_debug_snapshot!(recv_buff, @r###"
    CtrlPacket {
        vdiag: VerDiag {
            version: 1,
            diagnostic: Some(
                NoDiagnostic,
            ),
        },
        flags: StateFlags {
            state: Down,
            flag_poll: false,
            flag_final: false,
            flag_cpi: false,
            flag_auth_present: true,
            flag_demand: false,
            flag_multipoint: false,
        },
        detect_mult: 3,
        length: 48,
        snd_id: 1,
        rcv_id: 0,
        des_min_tx_int: 1000,
        req_min_rx_int: 1000,
        req_min_echo_rx_int: 0,
        auth_header: AuthHeader {
            typ: 2,
            lenth: 24,
            key_id: 1,
            __reserved_part_of_pass: 0,
        },
        auth_data: Md5(
            AuthMd5 {
                seq: 0,
                digest: [15, a8, 06, 20, 95, d7, a2, 3d, b2, 43, 5e, 22, 79, 1a, 28, a4],
            },
        ),
    }
    "###);
  }
}
