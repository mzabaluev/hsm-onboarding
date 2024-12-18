use hsm_onboarding::hsm::{HashicorpVaultHsm, Hsm};
use hsm_onboarding::{app::Message, Application, Bytes};

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use vaultrs::client::VaultClientSettingsBuilder;

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let message = Bytes(b"Hello, world".into());

    let vault_client_settings = VaultClientSettingsBuilder::default().build()?;
    let hsm = HashicorpVaultHsm::new(vault_client_settings)?;
    let (sender, receiver) = mpsc::channel::<Message>(16);
    let app = Application::new(Hsm::HashicorpVault(hsm), ReceiverStream::new(receiver));

    let join_handle = tokio::spawn(app.run());

    let (sig_sender, sig_receiver) = oneshot::channel();
    sender
        .send(Message::Sign(message.clone(), sig_sender))
        .await?;

    let signature = sig_receiver.await?;

    sender.send(Message::Verify(message, signature)).await?;

    drop(sender);
    join_handle.await??;

    Ok(())
}
