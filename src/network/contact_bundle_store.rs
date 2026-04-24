use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use super::contact_bundle::{
    verify_contact_bundle, ContactBundleGetRequest, ContactBundleGetResponse,
    ContactBundlePutRequest,
};
use super::did_profile::DidProfile;

pub struct ContactBundleStore {
    backend: ContactBundleStoreBackend,
}

enum ContactBundleStoreBackend {
    Sqlite(SqlitePool),
    Memory(Mutex<HashMap<String, String>>),
}

impl ContactBundleStore {
    pub async fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let db_path = data_dir.join("contact-bundles.sqlite3");
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .context("Invalid contact bundle sqlite path")?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .context("Failed to open contact bundle sqlite database")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS contact_bundles (
                contact_did TEXT PRIMARY KEY,
                profile_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            backend: ContactBundleStoreBackend::Sqlite(pool),
        })
    }

    pub fn open_memory() -> Self {
        Self {
            backend: ContactBundleStoreBackend::Memory(Mutex::new(HashMap::new())),
        }
    }

    pub async fn put(&self, request: ContactBundlePutRequest) -> Result<()> {
        request.validate()?;
        let profile_json = serde_json::to_string(&request.profile)
            .context("Failed to encode contact bundle profile")?;
        let updated_at = chrono::Utc::now().timestamp().max(0);

        match &self.backend {
            ContactBundleStoreBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO contact_bundles (contact_did, profile_json, updated_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(contact_did) DO UPDATE
                     SET profile_json = excluded.profile_json,
                         updated_at = excluded.updated_at",
                )
                .bind(&request.contact_did)
                .bind(profile_json)
                .bind(updated_at)
                .execute(pool)
                .await?;
            }
            ContactBundleStoreBackend::Memory(state) => {
                state.lock().await.insert(request.contact_did, profile_json);
            }
        }
        Ok(())
    }

    pub async fn get(&self, request: ContactBundleGetRequest) -> Result<ContactBundleGetResponse> {
        request.validate()?;
        let contact_did = request.contact_did.clone();
        let maybe_profile = match &self.backend {
            ContactBundleStoreBackend::Sqlite(pool) => {
                let row = sqlx::query_as::<_, (String,)>(
                    "SELECT profile_json FROM contact_bundles WHERE contact_did = ?1",
                )
                .bind(&contact_did)
                .fetch_optional(pool)
                .await?;
                row.map(|(profile_json,)| {
                    serde_json::from_str::<DidProfile>(&profile_json)
                        .context("Failed to decode stored contact bundle profile")
                })
                .transpose()?
            }
            ContactBundleStoreBackend::Memory(state) => state
                .lock()
                .await
                .get(&contact_did)
                .cloned()
                .map(|profile_json| {
                    serde_json::from_str::<DidProfile>(&profile_json)
                        .context("Failed to decode stored contact bundle profile")
                })
                .transpose()?,
        };

        if let Some(profile) = maybe_profile {
            verify_contact_bundle(&contact_did, &profile)?;
            Ok(ContactBundleGetResponse::with_profile(contact_did, profile))
        } else {
            Ok(ContactBundleGetResponse::empty(contact_did))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_did::encode_contact_did;
    use crate::network::discovery::build_local_did_profile_with_iroh_contact_endpoint;
    use serde_json::json;

    fn test_config() -> AppConfig {
        serde_json::from_value(json!({
            "agent": {
                "name": "bundle-owner",
                "role": "agent",
                "did": "did:nxf:test"
            },
            "network": {
                "listen_port": 9090,
                "bootstrap_nodes": [],
                "enable_mdns": false,
                "enable_kademlia": false,
                "transport_mode": "internet",
                "iroh": {
                    "relay_enabled": true,
                    "direct_enabled": false,
                    "relay_urls": ["https://relay.example.com"]
                },
                "mailbox": {
                    "endpoint": "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
                    "pool_endpoints": []
                }
            },
            "security": {
                "require_mtls": false,
                "max_message_size_bytes": 65536,
                "nonce_window_size": 64,
                "shadow_mode_enabled": false,
                "message_ttl_ms": 60000
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn roundtrip_put_and_get_profile() {
        let keypair = AgentKeyPair::generate("bundle-owner", "agent");
        let config = test_config();
        let endpoint_addr_json =
            crate::network::discovery::iroh::build_public_iroh_contact_endpoint_addr_json(
                &config.network.iroh,
                [4u8; 32],
            )
            .unwrap()
            .unwrap();
        let profile = build_local_did_profile_with_iroh_contact_endpoint(
            &keypair,
            &config,
            None,
            Some(&endpoint_addr_json),
        )
        .unwrap();
        let contact_did = encode_contact_did(&profile).unwrap();

        let store = ContactBundleStore::open_memory();
        store
            .put(ContactBundlePutRequest::new(
                contact_did.clone(),
                profile.clone(),
            ))
            .await
            .unwrap();

        let response = store
            .get(ContactBundleGetRequest::new(contact_did))
            .await
            .unwrap();
        assert_eq!(response.into_verified_profile().unwrap(), Some(profile));
    }
}
