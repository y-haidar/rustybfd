use std::mem::size_of;

use md5::{Digest, Md5};

use crate::packet::{AuthHeader, AuthMd5, AuthType, AuthTypeDiscriminants, CtrlPacket, StateFlags};

const MD5_CTRL_PKT_SIZE: usize =
  size_of::<CtrlPacket>() + size_of::<AuthHeader>() + size_of::<AuthMd5>();

pub fn check(
  len: usize,
  pkt: &CtrlPacket,
  // auth_header: &AuthHeader,
  data: &[u8],
  configured_auth_type: AuthTypeDiscriminants,
  pass: &Vec<u8>,
) -> bool {
  if len as u8 != pkt.length {
    return false;
  }
  if !pkt.state_and_flags.contains(StateFlags::F_AUTH_PRESENT) {
    if configured_auth_type == AuthTypeDiscriminants::NoneReserved {
      return true;
    } else {
      return false;
    }
  }
  let auth_header = pkt.get_auth_header(data);
  if auth_header.typ != configured_auth_type as u8 {
    return false;
  }
  let auth_type = auth_header.get_auth_type(data);
  // TODO: check seq number
  match auth_type {
    AuthType::NoneReserved(_) => todo!(),
    AuthType::Simple(_) => todo!(),
    AuthType::Md5(auth) => {
      if auth_header.lenth != (size_of::<AuthHeader>() + size_of::<AuthMd5>()) as u8 {
        return false;
      }

      let digest = Md5::new().chain_update(&data[..MD5_CTRL_PKT_SIZE - 16]);
      let digest = match pass.len() > 16 {
        true => {
          tracing::trace!("NOT SUPPORTED PASSWORD LENGTH {}", pass.len());
          // This does not work
          let pass = Md5::new().chain_update(&pass).finalize();
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
      digest.as_slice() == auth.digest
    }
    AuthType::MeticulousMd5(_) => todo!(),
    AuthType::Sha1(_) => todo!(),
    AuthType::MeticulousSha1(_) => todo!(),
  }
}
