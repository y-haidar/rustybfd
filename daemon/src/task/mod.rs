mod timer_cb;
pub use timer_cb::*;
pub mod timer_ctx;

#[derive(Debug, PartialEq)]
pub enum TimerType {
  Once,
  Infinite,
}

/// Taken from FRR (bfdd/bfd.c):
///
/// From section 6.5.2: trasmit interval should be randomly jittered
/// between 75% and 100% of nominal value, unless detect_mult is 1,
/// then should be between 75% and 90%.
#[inline]
pub fn add_jitter(duration: std::time::Duration, detect_mult: u8) -> std::time::Duration {
  if detect_mult == 0 {
    tracing::trace!("detect_mult should not be zero.");
    return duration;
  }
  let maxpercent = if detect_mult == 1 { 16 } else { 26 };
  let random = rand::random::<u32>();
  (duration * (75 + (random % maxpercent))) / 100
}
