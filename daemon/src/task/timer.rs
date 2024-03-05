use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedSender};

#[derive(Debug)]
pub struct Timer {
  pub tx: UnboundedSender<TimerMessage>,
}

#[derive(Debug)]
pub enum TimerMessage {
  Refresh,
}

#[derive(PartialEq)]
pub enum TimerType {
  Once,
  Infinite,
}

// Taken from https://github.com/zebra-rs/bgpd/blob/main/src/tasks/timer.rs
impl Timer {
  pub fn new<F, Fut>(duration: Duration, typ: TimerType, mut cb: F) -> Timer
  where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
  {
    let (tx, mut rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
      let mut interval = tokio::time::interval(duration);
      _ = interval.tick().await;
      loop {
        tokio::select! {
          _ = interval.tick() => {
            (cb)().await;
            if typ == TimerType::Once {
              break;
            }
          }
          message = rx.recv() => {
            match message {
              Some(TimerMessage::Refresh)=> {
                interval = tokio::time::interval(duration);
                _ = interval.tick().await;
              }
              None => break,
            }
          }
        }
      }
    });
    Timer { tx }
  }

  pub fn refresh(&self) {
    let _ = self.tx.send(TimerMessage::Refresh);
  }
}

/// Taken from FRR (bfdd/bfd.c):
///
/// From section 6.5.2: trasmit interval should be randomly jittered
/// between 75% and 100% of nominal value, unless detect_mult is 1,
/// then should be between 75% and 90%.
#[inline]
pub fn add_jitter(duration: Duration, detect_mult: u8) -> Duration {
  if detect_mult == 0 {
    tracing::trace!("detect_mult should not be zero.");
    return duration;
  }
  let maxpercent = if detect_mult == 1 { 16 } else { 26 };
  let random = rand::random::<u32>();
  (duration * (75 + (random % maxpercent))) / 100
}
