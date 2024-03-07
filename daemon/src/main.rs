use std::{sync::Arc, time::Duration};

use rustybfd::{
  bfd::test_impl::{Bfd, PeerCfg},
  packet::AuthTypeDiscriminants,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
  tracing_subscriber::registry()
    .with(fmt::layer())
    .with(EnvFilter::from_default_env())
    .init();

  let peers = vec![PeerCfg::new(
    "172.30.135.1:3784".parse().unwrap(),
    1,
    3,
    Duration::from_millis(600),
    Duration::from_millis(600),
    AuthTypeDiscriminants::Md5,
    Some(1),
    Arc::new(Some(b"some_random_key".to_vec())),
  )];
  Bfd::serve("172.30.135.50:3784".parse().unwrap(), peers, Arc::new(())).await;
}
