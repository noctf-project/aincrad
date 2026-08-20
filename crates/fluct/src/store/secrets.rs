use std::collections::HashMap;

use fluct::Error;
use k8s_openapi::api::core::v1::Secret;
use tokio::{
    join, select,
    sync::{RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{clients::KubernetesClient, crypto::hmac_sha256};

pub struct SecretsStore {
    client: KubernetesClient,
    root: String,
    secrets: RwLock<HashMap<String, Vec<u8>>>,
}

impl SecretsStore {
    pub fn new(client: KubernetesClient, root: &str) -> Self {
        Self {
            client,
            root: root.to_string(),
            secrets: RwLock::new(HashMap::new()),
        }
    }

    pub async fn derive_key(&self, store: &str, challenge: &str, role: &str) -> Option<Vec<u8>> {
        self.secrets
            .read()
            .await
            .get(store)
            .map(|k| hmac_sha256(k, challenge.as_bytes()))
            .map(|k| hmac_sha256(&k, role.as_bytes()))
    }

    pub async fn handle_secret_event(&self, secret: Option<Secret>) {
        match secret {
            Some(secret) => {
                if let Some(data) = secret.data {
                    info!("Root secrets {} updated", self.root);
                    let mut w = self.secrets.write().await;
                    w.clear();
                    for (k, v) in data {
                        w.insert(k, v.0);
                    }
                }
            }
            None => {
                warn!("Root secrets {} deleted", self.root);
                let mut w = self.secrets.write().await;
                w.clear();
            }
        }
    }

    async fn update(&self, cancel: CancellationToken, mut chan: mpsc::Receiver<Option<Secret>>) {
        loop {
            select! {
              Some(event) = chan.recv() => {
                self.handle_secret_event(event).await;
              },
              _ = cancel.cancelled() => {
                break;
              }
            }
        }
    }

    pub async fn run(&self, cancel: CancellationToken) -> Result<(), Error> {
        let (tx, rx) = mpsc::channel(8);
        join!(
            self.client
                .watch_object::<Secret>(cancel.clone(), &self.root, tx),
            self.update(cancel.clone(), rx)
        )
        .0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn test_secrets_store_derive_key() {
        let store = SecretsStore {
            client: KubernetesClient::new_dummy_for_tests(),
            root: "root".into(),
            secrets: RwLock::new(HashMap::new()),
        };

        // Missing key returns None
        assert!(
            store
                .derive_key("default", "my-chal", "flag")
                .await
                .is_none()
        );

        // Insert key
        {
            let mut w = store.secrets.write().await;
            w.insert("default".into(), b"root_secret_key".to_vec());
        }

        let key1 = store.derive_key("default", "my-chal", "flag").await;
        let key2 = store.derive_key("default", "my-chal", "flag").await;
        let key_challenge = store.derive_key("default", "my-chal", "challenge").await;

        assert!(key1.is_some());
        assert_eq!(key1, key2); // Deterministic
        assert_ne!(key1, key_challenge); // Different role -> different key
    }

    #[tokio::test]
    async fn test_secrets_store_handle_secret_event_lifecycle() {
        let store = SecretsStore::new(KubernetesClient::new_dummy_for_tests(), "aincrad-roots");

        let mut data = BTreeMap::new();
        data.insert(
            "ductf2025".to_string(),
            ByteString(b"secret_bytes".to_vec()),
        );

        let secret = Secret {
            data: Some(data),
            ..Default::default()
        };

        // Apply secret update event
        store.handle_secret_event(Some(secret)).await;

        let derived = store.derive_key("ductf2025", "my-chal", "flag").await;
        assert!(derived.is_some());

        // Delete secret event
        store.handle_secret_event(None).await;
        let derived_after = store.derive_key("ductf2025", "my-chal", "flag").await;
        assert!(derived_after.is_none());
    }
}
