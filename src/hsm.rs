mod hashicorp_vault;

use std::error::Error as StdError;

pub use hashicorp_vault::HashicorpVaultHsm;

use crate::{Bytes, Signature};

#[derive(Debug, thiserror::Error)]
/// HSM errors
pub enum Error {
    /// An error reported by the HSM client.
    #[error(transparent)]
    Client(Box<dyn StdError + Send + Sync>),
    /// Unexpected response from the backend, with a human-readable representation.
    #[error("unexpected response: {0}")]
    UnexpectedResponse(Box<str>),
    /// Failure to decode response from the backend.
    #[error("failed to decode response")]
    ResponseDecoding(#[source] Box<dyn StdError + Send + Sync>),
}

impl Error {
    pub fn client(error: impl StdError + Send + Sync + 'static) -> Self {
        Error::Client(Box::new(error))
    }

    pub fn unexpected_response(response: impl Into<String>) -> Self {
        Error::UnexpectedResponse(response.into().into_boxed_str())
    }

    pub fn response_decoding(error: impl StdError + Send + Sync + 'static) -> Self {
        Error::ResponseDecoding(Box::new(error))
    }
}

/// An HSM capable of signing and verifying messages.
pub enum Hsm {
    HashicorpVault(HashicorpVaultHsm),
}

impl Hsm {
    pub async fn sign(&self, message: Bytes) -> Result<Signature, Error> {
        match self {
            Hsm::HashicorpVault(hsm) => hsm.sign(message).await,
        }
    }

    pub async fn verify(&self, message: Bytes, signature: Signature) -> Result<bool, Error> {
        match self {
            Hsm::HashicorpVault(hsm) => hsm.verify(message, signature).await,
        }
    }
}
