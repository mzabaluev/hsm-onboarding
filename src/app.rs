use crate::hsm::{self, Hsm};
use crate::types::{Bytes, Signature};

use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tracing::debug;

use std::pin::pin;

/// A message to be signed or verified.
pub enum Message {
    Sign(Bytes, oneshot::Sender<Signature>),
    Verify(Bytes, Signature),
}

/// An application which reads a stream of messages to either sign or verify.
pub struct Application<S> {
    hsm: Hsm,
    // A stream of messages to be signed or verified.
    stream: S,
}

/// The application implementation.
impl<S> Application<S> {
    pub fn new(hsm: Hsm, stream: S) -> Self {
        Application { hsm, stream }
    }
}

impl<S> Application<S>
where
    S: Stream<Item = Message>,
{
    pub async fn run(self) -> Result<(), hsm::Error> {
        let mut stream = pin!(self.stream);
        while let Some(message) = stream.next().await {
            match message {
                Message::Sign(message, response) => {
                    let signature = self.hsm.sign(message).await?;
                    println!("Signed message: {:?}", signature);
                    response
                        .send(signature)
                        .unwrap_or_else(|_| debug!("response receiver was dropped"));
                }
                Message::Verify(message, signature) => {
                    let verified = self.hsm.verify(message, signature).await?;
                    println!("Verified message: {:?}", verified);
                }
            }
        }
        Ok(())
    }
}
