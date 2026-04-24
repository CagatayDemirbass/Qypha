use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use super::group_invite_bundle::{
    verify_group_invite_bundle, GroupInviteBundle, GroupInviteBundleGetRequest,
    GroupInviteBundleGetResponse, GroupInviteBundlePutRequest,
};

pub struct GroupInviteBundleStore {
    backend: GroupInviteBundleStoreBackend,
}

enum GroupInviteBundleStoreBackend {
    Sqlite(SqlitePool),
    Memory(Mutex<HashMap<(String, String), String>>),
}

impl GroupInviteBundleStore {
    pub async fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let db_path = data_dir.join("group-invite-bundles.sqlite3");
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .context("Invalid group invite bundle sqlite path")?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .context("Failed to open group invite bundle sqlite database")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS group_invite_bundles (
                issuer_contact_did TEXT NOT NULL,
                invite_id TEXT NOT NULL,
                bundle_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (issuer_contact_did, invite_id)
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            backend: GroupInviteBundleStoreBackend::Sqlite(pool),
        })
    }

    pub fn open_memory() -> Self {
        Self {
            backend: GroupInviteBundleStoreBackend::Memory(Mutex::new(HashMap::new())),
        }
    }

    pub async fn put(&self, request: GroupInviteBundlePutRequest) -> Result<()> {
        request.validate()?;
        let bundle_json = serde_json::to_string(&request.bundle)
            .context("Failed to encode group invite bundle")?;
        let updated_at = chrono::Utc::now().timestamp().max(0);

        match &self.backend {
            GroupInviteBundleStoreBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO group_invite_bundles (issuer_contact_did, invite_id, bundle_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(issuer_contact_did, invite_id) DO UPDATE
                     SET bundle_json = excluded.bundle_json,
                         updated_at = excluded.updated_at",
                )
                .bind(&request.issuer_contact_did)
                .bind(&request.bundle.invite_id)
                .bind(bundle_json)
                .bind(updated_at)
                .execute(pool)
                .await?;
            }
            GroupInviteBundleStoreBackend::Memory(state) => {
                state.lock().await.insert(
                    (
                        request.issuer_contact_did.clone(),
                        request.bundle.invite_id.clone(),
                    ),
                    bundle_json,
                );
            }
        }
        Ok(())
    }

    pub async fn get(
        &self,
        request: GroupInviteBundleGetRequest,
    ) -> Result<GroupInviteBundleGetResponse> {
        request.validate()?;
        let issuer_contact_did = request.issuer_contact_did.clone();
        let invite_id = request.invite_id.clone();
        let maybe_bundle = match &self.backend {
            GroupInviteBundleStoreBackend::Sqlite(pool) => {
                let row = sqlx::query_as::<_, (String,)>(
                    "SELECT bundle_json FROM group_invite_bundles
                     WHERE issuer_contact_did = ?1 AND invite_id = ?2",
                )
                .bind(&issuer_contact_did)
                .bind(&invite_id)
                .fetch_optional(pool)
                .await?;
                row.map(|(bundle_json,)| {
                    serde_json::from_str::<GroupInviteBundle>(&bundle_json)
                        .context("Failed to decode stored group invite bundle")
                })
                .transpose()?
            }
            GroupInviteBundleStoreBackend::Memory(state) => state
                .lock()
                .await
                .get(&(issuer_contact_did.clone(), invite_id.clone()))
                .cloned()
                .map(|bundle_json| {
                    serde_json::from_str::<GroupInviteBundle>(&bundle_json)
                        .context("Failed to decode stored group invite bundle")
                })
                .transpose()?,
        };

        if let Some(bundle) = maybe_bundle {
            verify_group_invite_bundle(&issuer_contact_did, &bundle)?;
            Ok(GroupInviteBundleGetResponse::with_bundle(
                issuer_contact_did,
                invite_id,
                bundle,
            ))
        } else {
            Ok(GroupInviteBundleGetResponse::empty(
                issuer_contact_did,
                invite_id,
            ))
        }
    }
}
