use std::mem::size_of;

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use derivative::Derivative;
use md5::Digest;
use strum_macros::{EnumDiscriminants, FromRepr};

fn fmt_u32_from_be(f: &u32, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
  let _ = fmt.write_str(&u32::from_be(*f).to_string());
  Ok(())
}
fn fmt_u8_slice_to_hex(f: &[u8], fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
  let _ = fmt.write_fmt(format_args!("{f:02x?}"));
  Ok(())
}

pub const MAX_CTRL_PKT_SIZE: usize =
  size_of::<CtrlPacket>() + size_of::<AuthHeader>() + size_of::<AuthSha1>();
pub const MD5_CTRL_PKT_SIZE: usize =
  size_of::<CtrlPacket>() + size_of::<AuthHeader>() + size_of::<AuthMd5>();

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
#[derive(PartialEq, Copy, Clone, Zeroable, Pod)]
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
impl Default for VerDiag {
  fn default() -> Self {
    Self(1 << 5)
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
bitflags! {
  /// Represents a set of flags.
  #[derive(Default, PartialEq, Copy, Clone)]
  #[repr(C)]
  pub struct StateFlags: u8 {
      const F_POLL = 0b00100000;
      const F_FINAL = 0b00010000;
      const F_CPI = 0b00001000;
      const F_AUTH_PRESENT = 0b00000100;
      const F_DEMAND = 0b00000010;
      /// This bit is reserved for future point-to-multipoint extensions to
      /// BFD. It MUST be zero on both transmit and receipt.
      const F_MULTIPOINT = 0b00000001;
  }
}

unsafe impl Zeroable for StateFlags {}
unsafe impl Pod for StateFlags {}

impl StateFlags {
  pub fn get_state(&self) -> State {
    State::from_repr((self.bits() >> 6) as usize).unwrap()
  }
}

#[derive(Default, Copy, Clone, Zeroable, Pod)]
#[repr(C)]
pub struct CtrlPacket {
  pub ver_and_diag: VerDiag,       /* Version and diagnostic */
  pub state_and_flags: StateFlags, /* State and flags */
  pub detect_mult: u8,
  pub length: u8,  /* Whole packet length */
  pub snd_id: u32, /* Sender ID, aka 'my discriminator' */
  pub rcv_id: u32, /* Receiver ID, aka 'your discriminator' */
  pub des_min_tx_int: u32,
  pub req_min_rx_int: u32,
  pub req_min_echo_rx_int: u32,
}
impl<'a> CtrlPacket {
  #[inline]
  pub fn snd_id_from_be(&self) -> u32 {
    u32::from_be(self.snd_id)
  }
  #[inline]
  pub fn rcv_id_from_be(&self) -> u32 {
    u32::from_be(self.rcv_id)
  }
  #[inline]
  pub fn des_min_tx_int_from_be(&self) -> u32 {
    u32::from_be(self.des_min_tx_int)
  }
  #[inline]
  pub fn req_min_rx_int_from_be(&self) -> u32 {
    u32::from_be(self.req_min_rx_int)
  }
  #[inline]
  pub fn req_min_echo_rx_int_from_be(&self) -> u32 {
    u32::from_be(self.req_min_echo_rx_int)
  }
  pub fn get_auth_header(&'a self, data: &'a [u8]) -> Option<&'a AuthHeader> {
    if self.state_and_flags.contains(StateFlags::F_AUTH_PRESENT) {
      Some(bytemuck::from_bytes(
        &data[size_of::<Self>()..size_of::<AuthHeader>() + size_of::<Self>()],
      ))
    } else {
      None
    }
  }
  pub fn read_bytes(len: usize, data: &'a [u8]) -> Option<&'a Self> {
    if len >= std::mem::size_of::<CtrlPacket>() {
      Some(bytemuck::from_bytes(&data[..size_of::<Self>()]))
    } else {
      None
    }
  }
}

#[derive(Debug, Default, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct AuthHeader {
  pub typ: u8,
  pub lenth: u8,
  pub key_id: u8,
  pub __reserved_part_of_pass: u8,
}
impl<'a> AuthHeader {
  /// `auth_data` includes and starts at `AuthHeader`
  pub fn get_auth_type(&'a self, data: &'a [u8]) -> AuthType<'a> {
    let auth_data = &data[size_of::<CtrlPacket>()..];
    // TODO: check if length was set correctly in all cases
    match self.get_auth_type_discriminants() {
      AuthTypeDiscriminants::NoneReserved => AuthType::NoneReserved(self.typ),
      AuthTypeDiscriminants::Simple => {
        AuthType::Simple(if self.lenth > size_of::<AuthSimple>() as u8 {
          panic!("return error instead")
        } else {
          let mut pass = [0u8; 16];
          pass[..self.lenth as usize].copy_from_slice(
            &auth_data[size_of::<Self>() - 1..self.lenth as usize + size_of::<Self>() - 1],
          );
          AuthSimple { pass }
        })
      }
      AuthTypeDiscriminants::Md5 => AuthType::Md5(bytemuck::from_bytes(
        &auth_data[size_of::<Self>()..size_of::<AuthMd5>() + size_of::<Self>()],
      )),
      AuthTypeDiscriminants::MeticulousMd5 => AuthType::Md5(bytemuck::from_bytes(
        &auth_data[size_of::<Self>()..size_of::<AuthMd5>() + size_of::<Self>()],
      )),
      AuthTypeDiscriminants::Sha1 => AuthType::Sha1(bytemuck::from_bytes(
        &auth_data[size_of::<Self>()..size_of::<AuthSha1>() + size_of::<Self>()],
      )),
      AuthTypeDiscriminants::MeticulousSha1 => AuthType::MeticulousSha1(bytemuck::from_bytes(
        &auth_data[size_of::<Self>()..size_of::<AuthSha1>() + size_of::<Self>()],
      )),
    }
  }
  pub fn get_auth_type_discriminants(&'a self) -> AuthTypeDiscriminants {
    AuthTypeDiscriminants::from_repr(self.typ).unwrap_or(AuthTypeDiscriminants::NoneReserved)
  }
}

#[derive(Debug, Copy, Clone, EnumDiscriminants)]
#[strum_discriminants(derive(FromRepr))]
#[repr(u8)]
#[non_exhaustive]
pub enum AuthType<'a> {
  /// This should never be used(the format is malformed). If it was used by sender, then drop the packet
  NoneReserved(u8),
  Simple(AuthSimple),
  Md5(&'a AuthMd5),
  MeticulousMd5(&'a AuthMd5),
  Sha1(&'a AuthSha1),
  MeticulousSha1(&'a AuthSha1),
}

#[derive(Derivative, Default, Copy, Clone, Zeroable, Pod)]
#[derivative(Debug)]
#[repr(C)]
pub struct AuthSimple {
  #[derivative(Debug(format_with = "fmt_u8_slice_to_hex"))]
  /// First byte is inside the last byte of AuthHeader
  pub pass: [u8; 16],
}

#[derive(Derivative, Default, Copy, Clone, Zeroable, Pod)]
#[derivative(Debug)]
#[repr(C)]
/// Section https://www.rfc-editor.org/rfc/rfc5880#section-4.3
/// length: 24 from RFC but - bytes in AuthHeader
pub struct AuthMd5 {
  #[derivative(Debug(format_with = "fmt_u32_from_be"))]
  /// For Keyed MD5 Authentication, this value is incremented occasionally. For
  /// Meticulous Keyed MD5 Authentication, this value is incremented for
  /// each successive packet transmitted for a session.
  pub seq: u32,
  #[derivative(Debug(format_with = "fmt_u8_slice_to_hex"))]
  /// Auth Key/Digest
  pub digest: [u8; 16],
}

#[derive(Derivative, Default, Copy, Clone, Zeroable, Pod)]
#[derivative(Debug)]
#[repr(C)]
/// Section https://www.rfc-editor.org/rfc/rfc5880#section-4.4
/// length: 28 from RFC but - bytes in AuthHeader
pub struct AuthSha1 {
  #[derivative(Debug(format_with = "fmt_u32_from_be"))]
  /// For Keyed SHA1 Authentication, this value is incremented occasionally. For
  /// Meticulous Keyed SHA1 Authentication, this value is incremented for
  /// each successive packet transmitted for a session.
  pub seq: u32,
  #[derivative(Debug(format_with = "fmt_u8_slice_to_hex"))]
  /// Auth Key/Digest
  pub digest: [u8; 20],
}

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
      .field("flags", &StateFlags::from_bits_truncate(self.bits()).0)
      .finish()
  }
}
impl std::fmt::Debug for CtrlPacket {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // let auth_type = self.auth_type();

    f.debug_struct("CtrlPacket")
      .field("ver_and_diag", &self.ver_and_diag)
      .field("state_and_flags", &self.state_and_flags)
      .field("detect_mult", &self.detect_mult)
      .field("length", &self.length)
      .field("snd_id", &self.snd_id_from_be())
      .field("rcv_id", &self.rcv_id_from_be())
      .field("des_min_tx_int", &self.des_min_tx_int_from_be())
      .field("req_min_rx_int", &self.req_min_rx_int_from_be())
      .field("req_min_echo_rx_int", &self.req_min_echo_rx_int_from_be())
      // .field("auth_header", &self.auth_header)
      // .field("auth_data", &auth_type)
      .finish()
  }
}

pub fn check<'a>(
  len: usize,
  data: &'a [u8],
  configured_auth_type: AuthTypeDiscriminants,
  pass: &Vec<u8>,
) -> Option<(&'a CtrlPacket, Option<&'a AuthHeader>, Option<AuthType<'a>>)> {
  let pkt = match CtrlPacket::read_bytes(len, data) {
    Some(v) => v,
    None => return None,
  };

  let auth_header = match (
    pkt.get_auth_header(data),
    configured_auth_type == AuthTypeDiscriminants::NoneReserved,
  ) {
    (None, true) => return Some((pkt, None, None)),
    (None, false) => return None,
    (Some(_), true) => return None,
    (Some(v), false) => v,
  };

  if auth_header.typ != configured_auth_type as u8 {
    return None;
  }
  let auth_type = auth_header.get_auth_type(data);
  // TODO: check seq number
  match auth_type {
    AuthType::NoneReserved(_) => todo!(),
    AuthType::Simple(_) => todo!(),
    AuthType::Md5(auth) => {
      if auth_header.lenth != (size_of::<AuthHeader>() + size_of::<AuthMd5>()) as u8 {
        return None;
      }

      let digest = md5::Md5::new().chain_update(&data[..MD5_CTRL_PKT_SIZE - 16]);
      let digest = match pass.len() > 16 {
        true => {
          tracing::trace!("NOT SUPPORTED PASSWORD LENGTH {}", pass.len());
          // This does not work
          let pass = md5::Md5::new().chain_update(&pass).finalize();
          digest
            // .chain_update(&pass.as_slice()[pass.len() - 16..])
            .chain_update(&pass)
            .finalize()
        }
        false => {
          let padding: Vec<u8> = (0..16 - pass.len()).map(|_| 0u8).collect();
          digest.chain_update(pass).chain_update(&padding).finalize()
        }
      };
      if digest.as_slice() != auth.digest {
        return None;
      }
    }
    AuthType::MeticulousMd5(_) => todo!(),
    AuthType::Sha1(_) => todo!(),
    AuthType::MeticulousSha1(_) => todo!(),
  }
  return Some((pkt, Some(auth_header), Some(auth_type)));
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  #[cfg_attr(miri, ignore)] // miri makes bytemuck give TargetAlignmentGreaterAndInputNotAligned need to research this
  fn test_example() {
    let sample_pkt_with_md5_auth = [
      0x20, 0x44, 0x03, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42,
      0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x02, 0x18, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x15, 0xa8, 0x06, 0x20, 0x95, 0xd7, 0xa2, 0x3d, 0xb2, 0x43, 0x5e, 0x22, 0x79,
      0x1a, 0x28, 0xa4,
    ];

    let pkt = CtrlPacket::read_bytes(sample_pkt_with_md5_auth.len(), &sample_pkt_with_md5_auth);
    insta::assert_debug_snapshot!(pkt, @r###"
    Some(
        CtrlPacket {
            ver_and_diag: VerDiag {
                version: 1,
                diagnostic: Some(
                    NoDiagnostic,
                ),
            },
            state_and_flags: StateFlags {
                state: Down,
                flags: F_AUTH_PRESENT,
            },
            detect_mult: 3,
            length: 48,
            snd_id: 1,
            rcv_id: 0,
            des_min_tx_int: 1000000,
            req_min_rx_int: 1000000,
            req_min_echo_rx_int: 0,
        },
    )
    "###);

    let auth_head = pkt
      .unwrap()
      .get_auth_header(&sample_pkt_with_md5_auth)
      .unwrap();
    insta::assert_debug_snapshot!(auth_head, @r###"
    Some(
        AuthHeader {
            typ: 2,
            lenth: 24,
            key_id: 1,
            __reserved_part_of_pass: 0,
        },
    )
    "###);

    let auth_type = auth_head.get_auth_type(&sample_pkt_with_md5_auth);
    insta::assert_debug_snapshot!(auth_type, @r###"
    Md5(
        AuthMd5 {
            seq: 0,
            digest: [15, a8, 06, 20, 95, d7, a2, 3d, b2, 43, 5e, 22, 79, 1a, 28, a4],
        },
    )
    "###);
  }
}
