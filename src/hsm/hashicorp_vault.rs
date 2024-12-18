use base64::prelude::*;
use tracing::debug;
use vaultrs::api::transit::requests::VerifySignedDataRequestBuilder;
use vaultrs::api::transit::responses::{SignDataResponse, VerifySignedDataResponse};
use vaultrs::client::{VaultClient, VaultClientSettings};
use vaultrs::transit;

use crate::hsm::Error;
use crate::{Bytes, Signature};

pub const VAULT_API_MOUNT: &str = "transit";
pub const KEY_NAME: &str = "hsm-onboarding";

/// Access to the Hashicorp Vault HSM
pub struct HashicorpVaultHsm {
    client: VaultClient,
}

impl HashicorpVaultHsm {
    pub fn new(settings: VaultClientSettings) -> Result<Self, Error> {
        let client = VaultClient::new(settings).map_err(Error::client)?;
        Ok(Self { client })
    }

    pub async fn sign(&self, message: Bytes) -> Result<Signature, Error> {
        let input = BASE64_STANDARD.encode(message);
        let res = transit::data::sign(&self.client, VAULT_API_MOUNT, KEY_NAME, &input, None)
            .await
            .map_err(Error::client)?;
        debug!("received response: {res:?}");
        let SignDataResponse { signature } = res;
        let rest = match signature.strip_prefix("vault:") {
            Some(suffix) => suffix,
            None => return Err(Error::unexpected_response(signature)),
        };
        let (derivation, sig_base64) = match rest.split_once(':') {
            Some((ver, rest)) => (ver, rest),
            None => return Err(Error::unexpected_response(signature)),
        };
        let sig_bytes = BASE64_STANDARD
            .decode(sig_base64)
            .map_err(Error::response_decoding)?;
        Ok(Signature {
            derivation: derivation.to_owned(),
            data: sig_bytes,
        })
    }

    pub async fn verify(&self, message: Bytes, signature: Signature) -> Result<bool, Error> {
        let input = BASE64_STANDARD.encode(message);
        let signature = format!(
            "vault:{}:{}",
            signature.derivation,
            BASE64_STANDARD.encode(signature.data)
        );
        let res = transit::data::verify(
            &self.client,
            VAULT_API_MOUNT,
            KEY_NAME,
            &input,
            Some(VerifySignedDataRequestBuilder::default().signature(signature)),
        )
        .await
        .map_err(Error::client)?;
        debug!("received response: {res:?}");
        let VerifySignedDataResponse { valid } = res;
        Ok(valid)
    }
}
