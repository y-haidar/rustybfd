use std::{marker::PhantomData, time::Duration};
use tokio::sync::mpsc;

#[async_trait::async_trait]
pub trait TimerCtxTrait {
  async fn callback(&mut self);
  async fn duration(&self) -> Duration;
}

pub struct TimerCtx<Ctx> {
  tx: mpsc::Sender<TimerCtxMessage>,
  _phantom: PhantomData<Ctx>,
}

impl<Ctx: TimerCtxTrait + Send + Sync + 'static> TimerCtx<Ctx> {
  pub fn new(mut ctx: Ctx) -> Self {
    let (tx, mut rx) = mpsc::channel(1024);

    tokio::spawn(async move {
      let mut duration = ctx.duration().await;
      let mut interval = tokio::time::interval(duration);
      _ = interval.tick().await;
      loop {
        tokio::select! {
          _ = interval.tick() => {
            ctx.callback().await;
            // if typ == super::TimerType::Once {
            //   break;
            // }
          }
          message = rx.recv() => {
            match message {
              Some(TimerCtxMessage::Refresh)=> {
                interval = tokio::time::interval(duration);
                _ = interval.tick().await;
              }
              Some(TimerCtxMessage::UpdateAndRefresh) => {
                // ctx = new;
                duration = ctx.duration().await;

                interval = tokio::time::interval(duration);
                _ = interval.tick().await;
              }
              None => break,
            }
          }
        }
      }
    });

    Self {
      tx,
      _phantom: PhantomData::default(),
    }
  }
  pub async fn refresh(&self) -> Result<(), ()> {
    self.tx.send(TimerCtxMessage::Refresh).await.map_err(|_| ())
  }
  pub async fn update_timer(&self) -> Result<(), ()> {
    self
      .tx
      .send(TimerCtxMessage::UpdateAndRefresh)
      .await
      .map_err(|_| ())
  }
}

#[derive(Debug)]
enum TimerCtxMessage {
  Refresh,
  UpdateAndRefresh,
  // UpdateAndRefresh(Ctx),
}
