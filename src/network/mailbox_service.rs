use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use super::contact_bundle::{ContactBundleGetRequest, ContactBundlePutRequest};
use super::contact_bundle_store::ContactBundleStore;
use super::contact_mailbox::{
    ContactMailboxAckRequest, ContactMailboxPollRequest, ContactMailboxPostRequest,
};
use super::contact_mailbox_store::ContactMailboxStore;
use super::group_invite_bundle::{GroupInviteBundleGetRequest, GroupInviteBundlePutRequest};
use super::group_invite_bundle_store::GroupInviteBundleStore;
use super::mailbox_bootstrap::{mailbox_bootstrap_pow_satisfies, verify_mailbox_bootstrap_token};
use super::mailbox_transport::{
    MailboxAckApiRequest, MailboxErrorResponse, MailboxPollApiRequest, MailboxPollItem,
    MailboxPollResult, MailboxPostApiRequest, MailboxPostReceipt, MAILBOX_CURSOR_TAIL,
};
use super::protocol::MailboxCapability;
use super::tor_transport::{TorManager, TorServiceRole};

const DEFAULT_MAILBOX_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_MAILBOX_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_MAILBOX_CLOCK_SKEW_SECS: i64 = 10 * 60;
const MAX_MAILBOX_POSTS_PER_MINUTE: usize = 240;
const MAX_MAILBOX_POLLS_PER_MINUTE: usize = 720;
const MAX_MAILBOX_ACKS_PER_MINUTE: usize = 1440;
const MAX_MAILBOX_POLL_LIMIT: usize = 128;
const MAX_MAILBOX_ACK_IDS: usize = 256;
const MAX_MAILBOX_NAMESPACE_LEN: usize = 256;
const MAX_MAILBOX_CAPABILITY_ID_LEN: usize = 128;
const MAX_MAILBOX_AUTH_TOKEN_B64_LEN: usize = 256;
const MAX_MAILBOX_ACCESS_KEY_B64_LEN: usize = 256;
const MAX_MAILBOX_CURSOR_LEN: usize = 32;
const MAX_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE: usize = 192;
const DEFAULT_MAILBOX_BOOTSTRAP_BUDGET_PER_HOUR: usize = 128;
const DEFAULT_MAILBOX_MAX_ACTIVE_NAMESPACES: usize = 2048;
const DEFAULT_MAILBOX_MIN_BOOTSTRAP_POW_DIFFICULTY_BITS: u8 = 12;
const MAX_MAILBOX_MIN_BOOTSTRAP_POW_DIFFICULTY_BITS: u8 = 24;
const MAILBOX_NAMESPACE_IDLE_GRACE_SECS: i64 = 24 * 60 * 60;
const MAILBOX_STORE_PAYLOAD_MAGIC: &str = "enc:v1:";
const MAILBOX_STORE_PAYLOAD_NONCE_LEN: usize = 12;
const MAILBOX_STORE_PAYLOAD_AAD_PREFIX: &[u8] = b"Qypha-Mailbox-Store-Payload-v1:";

#[derive(Clone)]
struct MailboxServiceState {
    store: Arc<MailboxStore>,
    contact_store: Arc<ContactMailboxStore>,
    contact_bundle_store: Arc<ContactBundleStore>,
    group_invite_bundle_store: Arc<GroupInviteBundleStore>,
}

struct MailboxStore {
    backend: MailboxStoreBackend,
    max_payload_bytes: usize,
    rate_limiter: MailboxRateLimiter,
    max_retention_ms: Option<u64>,
    relay_policy: MailboxRelayPolicy,
}

enum MailboxStoreBackend {
    Sqlite(SqlitePool),
    Memory(Mutex<MemoryMailboxState>),
}

#[derive(Default)]
struct MemoryMailboxState {
    namespaces: HashMap<String, MemoryMailboxNamespace>,
}

struct MemoryMailboxNamespace {
    capability_id: String,
    access_key_sha256: String,
    auth_token_sha256: String,
    created_at: i64,
    last_seen_at: i64,
    next_seq: i64,
    messages: VecDeque<MemoryMailboxMessage>,
}

struct MemoryMailboxMessage {
    seq: i64,
    message_id: String,
    payload_json: String,
    expires_at: i64,
}

struct MailboxRateLimiter {
    buckets: Mutex<HashMap<String, VecDeque<i64>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRelayPolicy {
    pub bootstrap_budget_per_hour: usize,
    pub max_active_namespaces: usize,
    pub min_bootstrap_pow_difficulty_bits: u8,
    pub bootstrap_issuer_allowlist: Vec<String>,
}

impl Default for MailboxRelayPolicy {
    fn default() -> Self {
        Self {
            bootstrap_budget_per_hour: DEFAULT_MAILBOX_BOOTSTRAP_BUDGET_PER_HOUR,
            max_active_namespaces: DEFAULT_MAILBOX_MAX_ACTIVE_NAMESPACES,
            min_bootstrap_pow_difficulty_bits: DEFAULT_MAILBOX_MIN_BOOTSTRAP_POW_DIFFICULTY_BITS,
            bootstrap_issuer_allowlist: Vec::new(),
        }
    }
}

impl MailboxRelayPolicy {
    fn normalized(self) -> Self {
        let mut bootstrap_issuer_allowlist = self
            .bootstrap_issuer_allowlist
            .into_iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        bootstrap_issuer_allowlist.sort();
        bootstrap_issuer_allowlist.dedup();
        Self {
            bootstrap_budget_per_hour: self.bootstrap_budget_per_hour.max(1),
            max_active_namespaces: self.max_active_namespaces.max(1),
            min_bootstrap_pow_difficulty_bits: self
                .min_bootstrap_pow_difficulty_bits
                .min(MAX_MAILBOX_MIN_BOOTSTRAP_POW_DIFFICULTY_BITS),
            bootstrap_issuer_allowlist,
        }
    }

    pub fn validate(&self) -> Result<()> {
        for issuer in &self.bootstrap_issuer_allowlist {
            if issuer.len() != 64 || !issuer.bytes().all(|b| b.is_ascii_hexdigit()) {
                anyhow::bail!("Mailbox bootstrap issuer allowlist entry is invalid: {issuer}");
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct MailboxInfoResponse {
    service: &'static str,
    version: u8,
}

impl MailboxStore {
    async fn open(
        data_dir: &Path,
        max_payload_bytes: usize,
        relay_policy: MailboxRelayPolicy,
    ) -> Result<Self> {
        let relay_policy = relay_policy.normalized();
        std::fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let db_path = data_dir.join("mailbox.sqlite3");
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .context("Invalid mailbox sqlite path")?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .context("Failed to open mailbox sqlite database")?;

        sqlx::query("PRAGMA journal_mode=WAL;")
            .execute(&pool)
            .await
            .ok();
        sqlx::query("PRAGMA foreign_keys=ON;")
            .execute(&pool)
            .await
            .ok();

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mailbox_namespaces (
                namespace TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL,
                access_key_sha256 TEXT NOT NULL DEFAULT '',
                auth_token_sha256 TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await?;
        let _ = sqlx::query(
            "ALTER TABLE mailbox_namespaces
             ADD COLUMN access_key_sha256 TEXT NOT NULL DEFAULT ''",
        )
        .execute(&pool)
        .await;
        let _ = sqlx::query(
            "ALTER TABLE mailbox_namespaces
             ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&pool)
        .await;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mailbox_messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(namespace, message_id)
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_mailbox_messages_namespace_seq
             ON mailbox_messages(namespace, seq)",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_mailbox_messages_expiry
             ON mailbox_messages(expires_at)",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            backend: MailboxStoreBackend::Sqlite(pool),
            max_retention_ms: None,
            max_payload_bytes,
            rate_limiter: MailboxRateLimiter::default(),
            relay_policy,
        })
    }

    fn open_memory(
        max_payload_bytes: usize,
        max_retention_ms: u64,
        relay_policy: MailboxRelayPolicy,
    ) -> Self {
        Self {
            backend: MailboxStoreBackend::Memory(Mutex::new(MemoryMailboxState::default())),
            max_payload_bytes,
            rate_limiter: MailboxRateLimiter::default(),
            max_retention_ms: Some(max_retention_ms),
            relay_policy: relay_policy.normalized(),
        }
    }

    async fn authorize(
        &self,
        namespace: &str,
        capability_id: &str,
        access_key_b64: &str,
        auth_token_b64: &str,
        bootstrap_token: Option<&super::protocol::MailboxBootstrapToken>,
    ) -> Result<()> {
        validate_access_request(namespace, capability_id, access_key_b64, auth_token_b64)?;
        let access_key_sha256 = access_digest(access_key_b64);
        let auth_token_sha256 = auth_digest(auth_token_b64);
        let capability = MailboxCapability {
            capability_id: capability_id.to_string(),
            access_key_b64: access_key_b64.to_string(),
            auth_token_b64: auth_token_b64.to_string(),
            bootstrap_token: bootstrap_token.cloned(),
        };
        let now = chrono::Utc::now().timestamp();
        match &self.backend {
            MailboxStoreBackend::Sqlite(pool) => {
                let existing = sqlx::query_as::<_, (String, String, String)>(
                    "SELECT capability_id, access_key_sha256, auth_token_sha256
                     FROM mailbox_namespaces
                     WHERE namespace = ?1",
                )
                .bind(namespace)
                .fetch_optional(pool)
                .await?;

                if existing.is_none() {
                    let bootstrap_token = bootstrap_token.ok_or_else(|| {
                        anyhow::anyhow!("Mailbox bootstrap token required for new namespace")
                    })?;
                    verify_mailbox_bootstrap_token(
                        bootstrap_token,
                        None,
                        namespace,
                        &capability,
                        true,
                    )?;
                    self.enforce_bootstrap_admission_policy(bootstrap_token)?;
                    self.enforce_bootstrap_quota().await?;
                    let active_namespaces = self.active_namespace_count().await?;
                    if active_namespaces >= self.relay_policy.max_active_namespaces {
                        anyhow::bail!(
                            "Mailbox relay namespace quota exceeded: {} active namespaces exceeds limit of {}",
                            active_namespaces,
                            self.relay_policy.max_active_namespaces
                        );
                    }
                    sqlx::query(
                        "INSERT OR IGNORE INTO mailbox_namespaces
                            (namespace, capability_id, access_key_sha256, auth_token_sha256, created_at, last_seen_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )
                    .bind(namespace)
                    .bind(capability_id)
                    .bind(&access_key_sha256)
                    .bind(&auth_token_sha256)
                    .bind(now)
                    .bind(now)
                    .execute(pool)
                    .await?;
                }

                let row = sqlx::query_as::<_, (String, String, String)>(
                    "SELECT capability_id, access_key_sha256, auth_token_sha256
                     FROM mailbox_namespaces
                     WHERE namespace = ?1",
                )
                .bind(namespace)
                .fetch_one(pool)
                .await?;

                let row_access_key = if row.1.is_empty() {
                    sqlx::query(
                        "UPDATE mailbox_namespaces
                         SET access_key_sha256 = ?2, last_seen_at = ?3
                         WHERE namespace = ?1 AND access_key_sha256 = ''",
                    )
                    .bind(namespace)
                    .bind(&access_key_sha256)
                    .bind(now)
                    .execute(pool)
                    .await?;
                    access_key_sha256.as_str()
                } else {
                    row.1.as_str()
                };

                if row.0 != capability_id
                    || row_access_key != access_key_sha256
                    || row.2 != auth_token_sha256
                {
                    anyhow::bail!("Mailbox capability rejected");
                }
                sqlx::query("UPDATE mailbox_namespaces SET last_seen_at = ?2 WHERE namespace = ?1")
                    .bind(namespace)
                    .bind(now)
                    .execute(pool)
                    .await?;
            }
            MailboxStoreBackend::Memory(state) => {
                let mut state = state.lock().await;
                if !state.namespaces.contains_key(namespace) {
                    let bootstrap_token = bootstrap_token.ok_or_else(|| {
                        anyhow::anyhow!("Mailbox bootstrap token required for new namespace")
                    })?;
                    verify_mailbox_bootstrap_token(
                        bootstrap_token,
                        None,
                        namespace,
                        &capability,
                        true,
                    )?;
                    self.enforce_bootstrap_admission_policy(bootstrap_token)?;
                    self.enforce_bootstrap_quota().await?;
                    if state.namespaces.len() >= self.relay_policy.max_active_namespaces {
                        anyhow::bail!(
                            "Mailbox relay namespace quota exceeded: {} active namespaces exceeds limit of {}",
                            state.namespaces.len(),
                            self.relay_policy.max_active_namespaces
                        );
                    }
                }
                let namespace_state = state
                    .namespaces
                    .entry(namespace.to_string())
                    .or_insert_with(|| MemoryMailboxNamespace {
                        capability_id: capability_id.to_string(),
                        access_key_sha256: access_key_sha256.clone(),
                        auth_token_sha256: auth_token_sha256.clone(),
                        created_at: now,
                        last_seen_at: now,
                        next_seq: 1,
                        messages: VecDeque::new(),
                    });
                if namespace_state.capability_id != capability_id
                    || namespace_state.access_key_sha256 != access_key_sha256
                    || namespace_state.auth_token_sha256 != auth_token_sha256
                {
                    anyhow::bail!("Mailbox capability rejected");
                }
                namespace_state.last_seen_at = now;
            }
        }
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        match &self.backend {
            MailboxStoreBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM mailbox_messages WHERE expires_at <= ?1")
                    .bind(now)
                    .execute(pool)
                    .await?;
                sqlx::query(
                    "DELETE FROM mailbox_namespaces
                     WHERE last_seen_at <= ?1
                       AND NOT EXISTS (
                           SELECT 1
                           FROM mailbox_messages
                           WHERE mailbox_messages.namespace = mailbox_namespaces.namespace
                       )",
                )
                .bind(now.saturating_sub(MAILBOX_NAMESPACE_IDLE_GRACE_SECS))
                .execute(pool)
                .await?;
            }
            MailboxStoreBackend::Memory(state) => {
                let mut state = state.lock().await;
                for namespace in state.namespaces.values_mut() {
                    namespace
                        .messages
                        .retain(|message| message.expires_at > now);
                }
                state.namespaces.retain(|_, namespace| {
                    !(namespace.messages.is_empty()
                        && namespace.last_seen_at
                            <= now.saturating_sub(MAILBOX_NAMESPACE_IDLE_GRACE_SECS))
                });
            }
        }
        Ok(())
    }

    async fn post(&self, request: MailboxPostApiRequest) -> Result<MailboxPostReceipt> {
        self.authorize(
            &request.namespace,
            &request.capability_id,
            &request.access_key_b64,
            &request.auth_token_b64,
            request.bootstrap_token.as_ref(),
        )
        .await?;
        self.rate_limiter
            .check(
                rate_limit_key(
                    "post",
                    &request.namespace,
                    &request.capability_id,
                    &request.access_key_b64,
                    &request.auth_token_b64,
                ),
                MAX_MAILBOX_POSTS_PER_MINUTE,
                60,
            )
            .await?;
        self.cleanup_expired().await?;
        validate_message_ingress(&request.namespace, &request.message)?;

        let payload_json =
            serde_json::to_string(&request.message).context("Failed to encode mailbox payload")?;
        if payload_json.len() > self.max_payload_bytes {
            anyhow::bail!(
                "Mailbox payload too large: {} bytes exceeds relay limit of {} bytes",
                payload_json.len(),
                self.max_payload_bytes
            );
        }
        let stored_payload_json = encrypt_store_payload(
            &request.namespace,
            &request.capability_id,
            &request.auth_token_b64,
            &payload_json,
        )
        .context("Failed to encrypt mailbox payload for at-rest storage")?;
        let expires_at = clamp_expiry(request.message.ttl_ms, self.max_retention_ms);
        let seq = match &self.backend {
            MailboxStoreBackend::Sqlite(pool) => {
                if let Some(existing_seq) = sqlx::query_as::<_, (i64,)>(
                    "SELECT seq FROM mailbox_messages
                     WHERE namespace = ?1 AND message_id = ?2",
                )
                .bind(&request.namespace)
                .bind(&request.message.message_id)
                .fetch_optional(pool)
                .await?
                .map(|row| row.0)
                {
                    return Ok(MailboxPostReceipt {
                        message_id: request.message.message_id,
                        server_cursor: Some(existing_seq.to_string()),
                    });
                }
                let pending_messages = sqlx::query_as::<_, (i64,)>(
                    "SELECT COUNT(*) FROM mailbox_messages WHERE namespace = ?1",
                )
                .bind(&request.namespace)
                .fetch_one(pool)
                .await?
                .0;
                if pending_messages >= MAX_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE as i64 {
                    anyhow::bail!(
                        "Mailbox namespace backlog full: {} pending messages exceeds limit of {}",
                        pending_messages,
                        MAX_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE
                    );
                }
                sqlx::query(
                    "INSERT OR IGNORE INTO mailbox_messages
                        (namespace, message_id, created_at, expires_at, payload_json)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .bind(&request.namespace)
                .bind(&request.message.message_id)
                .bind(request.message.created_at as i64)
                .bind(expires_at as i64)
                .bind(stored_payload_json)
                .execute(pool)
                .await?;

                sqlx::query_as::<_, (i64,)>(
                    "SELECT seq FROM mailbox_messages
                     WHERE namespace = ?1 AND message_id = ?2",
                )
                .bind(&request.namespace)
                .bind(&request.message.message_id)
                .fetch_one(pool)
                .await?
                .0
            }
            MailboxStoreBackend::Memory(state) => {
                let mut state = state.lock().await;
                let namespace_state = state
                    .namespaces
                    .get_mut(&request.namespace)
                    .ok_or_else(|| anyhow::anyhow!("Mailbox namespace not found"))?;
                if let Some(existing) = namespace_state
                    .messages
                    .iter()
                    .find(|message| message.message_id == request.message.message_id)
                {
                    existing.seq
                } else {
                    if namespace_state.messages.len() >= MAX_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE
                    {
                        anyhow::bail!(
                            "Mailbox namespace backlog full: {} pending messages exceeds limit of {}",
                            namespace_state.messages.len(),
                            MAX_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE
                        );
                    }
                    let seq = namespace_state.next_seq;
                    namespace_state.next_seq = namespace_state.next_seq.saturating_add(1);
                    namespace_state.messages.push_back(MemoryMailboxMessage {
                        seq,
                        message_id: request.message.message_id.clone(),
                        payload_json,
                        expires_at: expires_at as i64,
                    });
                    seq
                }
            }
        };

        Ok(MailboxPostReceipt {
            message_id: request.message.message_id,
            server_cursor: Some(seq.to_string()),
        })
    }

    async fn poll(&self, request: MailboxPollApiRequest) -> Result<MailboxPollResult> {
        self.authorize(
            &request.namespace,
            &request.capability_id,
            &request.access_key_b64,
            &request.auth_token_b64,
            request.bootstrap_token.as_ref(),
        )
        .await?;
        self.rate_limiter
            .check(
                rate_limit_key(
                    "poll",
                    &request.namespace,
                    &request.capability_id,
                    &request.access_key_b64,
                    &request.auth_token_b64,
                ),
                MAX_MAILBOX_POLLS_PER_MINUTE,
                60,
            )
            .await?;
        self.cleanup_expired().await?;
        if request.cursor.as_deref() == Some(MAILBOX_CURSOR_TAIL) {
            let tail_cursor = self.current_cursor(&request.namespace).await?;
            return Ok(MailboxPollResult {
                items: Vec::new(),
                next_cursor: Some(tail_cursor.to_string()),
            });
        }
        let limit = request.limit.clamp(1, MAX_MAILBOX_POLL_LIMIT);
        let cursor = parse_mailbox_cursor(request.cursor.as_deref())?;
        match &self.backend {
            MailboxStoreBackend::Sqlite(pool) => {
                let rows = sqlx::query_as::<_, (i64, String)>(
                    "SELECT seq, payload_json
                     FROM mailbox_messages
                     WHERE namespace = ?1 AND seq > ?2
                     ORDER BY seq ASC
                     LIMIT ?3",
                )
                .bind(&request.namespace)
                .bind(cursor)
                .bind(limit as i64)
                .fetch_all(pool)
                .await?;

                let mut items = Vec::with_capacity(rows.len());
                let mut next_cursor = request.cursor.clone();
                for (seq, payload_json) in rows {
                    let payload_json = decrypt_store_payload(
                        &request.namespace,
                        &request.capability_id,
                        &request.auth_token_b64,
                        &payload_json,
                    )
                    .context("Failed to decrypt stored mailbox payload")?;
                    let message = serde_json::from_str(&payload_json)
                        .context("Failed to decode stored mailbox payload")?;
                    next_cursor = Some(seq.to_string());
                    items.push(MailboxPollItem {
                        envelope_id: seq.to_string(),
                        message,
                    });
                }

                Ok(MailboxPollResult { items, next_cursor })
            }
            MailboxStoreBackend::Memory(state) => {
                let state = state.lock().await;
                let namespace_state = state
                    .namespaces
                    .get(&request.namespace)
                    .ok_or_else(|| anyhow::anyhow!("Mailbox namespace not found"))?;
                let mut items = Vec::new();
                let mut next_cursor = request.cursor.clone();
                for message in namespace_state
                    .messages
                    .iter()
                    .filter(|message| message.seq > cursor)
                    .take(limit)
                {
                    let decoded = serde_json::from_str(&message.payload_json)
                        .context("Failed to decode stored mailbox payload")?;
                    next_cursor = Some(message.seq.to_string());
                    items.push(MailboxPollItem {
                        envelope_id: message.seq.to_string(),
                        message: decoded,
                    });
                }
                Ok(MailboxPollResult { items, next_cursor })
            }
        }
    }

    async fn ack(&self, request: MailboxAckApiRequest) -> Result<()> {
        self.authorize(
            &request.namespace,
            &request.capability_id,
            &request.access_key_b64,
            &request.auth_token_b64,
            request.bootstrap_token.as_ref(),
        )
        .await?;
        self.rate_limiter
            .check(
                rate_limit_key(
                    "ack",
                    &request.namespace,
                    &request.capability_id,
                    &request.access_key_b64,
                    &request.auth_token_b64,
                ),
                MAX_MAILBOX_ACKS_PER_MINUTE,
                60,
            )
            .await?;
        if request.envelope_ids.len() > MAX_MAILBOX_ACK_IDS {
            anyhow::bail!(
                "Mailbox ack batch too large: {} ids exceeds limit of {}",
                request.envelope_ids.len(),
                MAX_MAILBOX_ACK_IDS
            );
        }
        for envelope_id in &request.envelope_ids {
            validate_envelope_id(envelope_id)?;
        }
        Ok(())
    }

    async fn current_cursor(&self, namespace: &str) -> Result<i64> {
        match &self.backend {
            MailboxStoreBackend::Sqlite(pool) => {
                let row = sqlx::query_as::<_, (Option<i64>,)>(
                    "SELECT MAX(seq) FROM mailbox_messages WHERE namespace = ?1",
                )
                .bind(namespace)
                .fetch_one(pool)
                .await?;
                Ok(row.0.unwrap_or(0))
            }
            MailboxStoreBackend::Memory(state) => {
                let state = state.lock().await;
                Ok(state
                    .namespaces
                    .get(namespace)
                    .map(|namespace_state| namespace_state.next_seq.saturating_sub(1))
                    .unwrap_or(0))
            }
        }
    }

    async fn active_namespace_count(&self) -> Result<usize> {
        match &self.backend {
            MailboxStoreBackend::Sqlite(pool) => Ok(sqlx::query_as::<_, (i64,)>(
                "SELECT COUNT(*) FROM mailbox_namespaces",
            )
            .fetch_one(pool)
            .await?
            .0
            .max(0) as usize),
            MailboxStoreBackend::Memory(state) => Ok(state.lock().await.namespaces.len()),
        }
    }

    async fn enforce_bootstrap_quota(&self) -> Result<()> {
        self.rate_limiter
            .check(
                "bootstrap:global".to_string(),
                self.relay_policy.bootstrap_budget_per_hour,
                60 * 60,
            )
            .await
            .with_context(|| {
                format!(
                    "Mailbox relay bootstrap budget exceeded (limit {} per hour)",
                    self.relay_policy.bootstrap_budget_per_hour
                )
            })
    }

    fn enforce_bootstrap_admission_policy(
        &self,
        bootstrap_token: &super::protocol::MailboxBootstrapToken,
    ) -> Result<()> {
        let issuer_key = bootstrap_token
            .issuer_verifying_key_hex
            .to_ascii_lowercase();
        if !self.relay_policy.bootstrap_issuer_allowlist.is_empty()
            && !self
                .relay_policy
                .bootstrap_issuer_allowlist
                .iter()
                .any(|allowed| allowed == &issuer_key)
        {
            anyhow::bail!("Mailbox bootstrap issuer is not allowlisted");
        }
        if self.relay_policy.min_bootstrap_pow_difficulty_bits > 0 {
            if bootstrap_token.pow_difficulty_bits
                < self.relay_policy.min_bootstrap_pow_difficulty_bits
            {
                anyhow::bail!(
                    "Mailbox bootstrap token PoW below required difficulty of {} bits",
                    self.relay_policy.min_bootstrap_pow_difficulty_bits
                );
            }
            if !mailbox_bootstrap_pow_satisfies(
                bootstrap_token,
                self.relay_policy.min_bootstrap_pow_difficulty_bits,
            ) {
                anyhow::bail!(
                    "Mailbox bootstrap token PoW below required difficulty of {} bits",
                    self.relay_policy.min_bootstrap_pow_difficulty_bits
                );
            }
        }
        Ok(())
    }
}

impl Default for MailboxRateLimiter {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }
}

impl MailboxRateLimiter {
    async fn check(&self, key: String, limit: usize, window_secs: i64) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now.saturating_sub(window_secs);
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets.entry(key).or_default();
        while let Some(ts) = bucket.front().copied() {
            if ts > cutoff {
                break;
            }
            bucket.pop_front();
        }
        if bucket.len() >= limit {
            anyhow::bail!("Mailbox rate limit exceeded");
        }
        bucket.push_back(now);
        Ok(())
    }
}

fn parse_mailbox_cursor(cursor: Option<&str>) -> Result<i64> {
    let Some(raw_cursor) = cursor else {
        return Ok(0);
    };
    let cursor = raw_cursor.trim();
    if cursor.is_empty() {
        anyhow::bail!("Mailbox cursor must not be blank when supplied");
    }
    if cursor == MAILBOX_CURSOR_TAIL {
        anyhow::bail!("Mailbox tail cursor must use the reserved sentinel");
    }
    if cursor.len() > MAX_MAILBOX_CURSOR_LEN {
        anyhow::bail!(
            "Mailbox cursor too long: {} bytes exceeds limit of {}",
            cursor.len(),
            MAX_MAILBOX_CURSOR_LEN
        );
    }
    if !cursor.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("Mailbox cursor must be a non-negative integer");
    }
    cursor
        .parse::<i64>()
        .context("Mailbox cursor must be a non-negative integer")
}

fn validate_access_request(
    namespace: &str,
    capability_id: &str,
    access_key_b64: &str,
    auth_token_b64: &str,
) -> Result<()> {
    validate_mailbox_text_field("namespace", namespace, MAX_MAILBOX_NAMESPACE_LEN)?;
    if !namespace.starts_with("mailbox:") {
        anyhow::bail!("Mailbox namespace must start with 'mailbox:'");
    }
    validate_mailbox_text_field(
        "capability_id",
        capability_id,
        MAX_MAILBOX_CAPABILITY_ID_LEN,
    )?;
    validate_mailbox_text_field("access key", access_key_b64, MAX_MAILBOX_ACCESS_KEY_B64_LEN)?;
    validate_mailbox_text_field("auth token", auth_token_b64, MAX_MAILBOX_AUTH_TOKEN_B64_LEN)?;
    let decoded_access_key = decode_mailbox_secret("access key", access_key_b64)?;
    if decoded_access_key.len() < 16 {
        anyhow::bail!("Mailbox access key must decode to at least 16 bytes");
    }
    let decoded = decode_mailbox_auth_token(auth_token_b64)?;
    if decoded.len() < 16 {
        anyhow::bail!("Mailbox auth token must decode to at least 16 bytes");
    }
    Ok(())
}

fn validate_mailbox_text_field(field_name: &str, value: &str, limit: usize) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Mailbox {field_name} must not be empty");
    }
    if trimmed.len() > limit {
        anyhow::bail!(
            "Mailbox {field_name} too long: {} bytes exceeds limit of {}",
            trimmed.len(),
            limit
        );
    }
    if !trimmed.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        anyhow::bail!("Mailbox {field_name} must use visible ASCII without whitespace");
    }
    Ok(())
}

fn decode_mailbox_auth_token(auth_token_b64: &str) -> Result<Vec<u8>> {
    decode_mailbox_secret("auth token", auth_token_b64)
}

fn decode_mailbox_secret(label: &str, value_b64: &str) -> Result<Vec<u8>> {
    BASE64_URL_SAFE_NO_PAD
        .decode(value_b64.as_bytes())
        .or_else(|_| BASE64_STANDARD.decode(value_b64.as_bytes()))
        .with_context(|| format!("Mailbox {label} must be valid base64"))
}

fn validate_envelope_id(envelope_id: &str) -> Result<()> {
    if envelope_id.is_empty() || envelope_id.len() > MAX_MAILBOX_CURSOR_LEN {
        anyhow::bail!("Mailbox envelope id must be present and reasonably bounded");
    }
    if !envelope_id.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("Mailbox envelope id must be numeric");
    }
    Ok(())
}

fn rate_limit_key(
    action: &str,
    namespace: &str,
    capability_id: &str,
    access_key_b64: &str,
    auth_token_b64: &str,
) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        action,
        namespace,
        capability_id,
        access_digest(access_key_b64),
        auth_digest(auth_token_b64)
    )
}

fn derive_store_payload_key(
    namespace: &str,
    capability_id: &str,
    auth_token_b64: &str,
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(
        Some(b"Qypha-Mailbox-Store-Payload-Key-v1"),
        auth_token_b64.as_bytes(),
    );
    let mut info = Vec::with_capacity(namespace.len() + capability_id.len() + 1);
    info.extend_from_slice(namespace.as_bytes());
    info.push(0);
    info.extend_from_slice(capability_id.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF expand for mailbox store payload key should not fail");
    key
}

fn store_payload_aad(namespace: &str, capability_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        MAILBOX_STORE_PAYLOAD_AAD_PREFIX.len() + namespace.len() + capability_id.len() + 1,
    );
    aad.extend_from_slice(MAILBOX_STORE_PAYLOAD_AAD_PREFIX);
    aad.extend_from_slice(namespace.as_bytes());
    aad.push(0);
    aad.extend_from_slice(capability_id.as_bytes());
    aad
}

fn encrypt_store_payload(
    namespace: &str,
    capability_id: &str,
    auth_token_b64: &str,
    payload_json: &str,
) -> Result<String> {
    let key = derive_store_payload_key(namespace, capability_id, auth_token_b64);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce_bytes = rand::random::<[u8; MAILBOX_STORE_PAYLOAD_NONCE_LEN]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = store_payload_aad(namespace, capability_id);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: payload_json.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Mailbox store payload encryption failed"))?;
    let mut blob = Vec::with_capacity(MAILBOX_STORE_PAYLOAD_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(format!(
        "{}{}",
        MAILBOX_STORE_PAYLOAD_MAGIC,
        BASE64_STANDARD.encode(blob)
    ))
}

fn decrypt_store_payload(
    namespace: &str,
    capability_id: &str,
    auth_token_b64: &str,
    stored_payload: &str,
) -> Result<String> {
    if !stored_payload.starts_with(MAILBOX_STORE_PAYLOAD_MAGIC) {
        return Ok(stored_payload.to_string());
    }
    let encoded = &stored_payload[MAILBOX_STORE_PAYLOAD_MAGIC.len()..];
    let blob = BASE64_STANDARD
        .decode(encoded)
        .context("Stored mailbox payload is not valid base64")?;
    if blob.len() < MAILBOX_STORE_PAYLOAD_NONCE_LEN + 16 {
        anyhow::bail!("Stored mailbox payload is truncated");
    }
    let key = derive_store_payload_key(namespace, capability_id, auth_token_b64);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&blob[..MAILBOX_STORE_PAYLOAD_NONCE_LEN]);
    let ciphertext = &blob[MAILBOX_STORE_PAYLOAD_NONCE_LEN..];
    let aad = store_payload_aad(namespace, capability_id);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Stored mailbox payload failed integrity check"))?;
    String::from_utf8(plaintext).context("Stored mailbox payload is not valid UTF-8")
}

fn namespace_group_id(namespace: &str) -> &str {
    let trimmed = namespace.trim();
    let without_prefix = trimmed.strip_prefix("mailbox:").unwrap_or(trimmed);
    without_prefix
        .split(":epoch:")
        .next()
        .unwrap_or(without_prefix)
}

fn validate_message_ingress(
    namespace: &str,
    message: &crate::network::protocol::GroupMailboxMessage,
) -> Result<()> {
    if message.version != 1 {
        anyhow::bail!("Unsupported mailbox message version {}", message.version);
    }
    if message.message_id.trim().is_empty() || message.message_id.len() > 128 {
        anyhow::bail!("Mailbox message_id must be present and at most 128 bytes");
    }
    if message.group_id.trim().is_empty() {
        anyhow::bail!("Mailbox message group_id must not be empty");
    }
    if namespace_group_id(namespace) != message.group_id {
        anyhow::bail!("Mailbox namespace/group_id mismatch");
    }
    if message.ciphertext.is_empty() {
        anyhow::bail!("Mailbox ciphertext must not be empty");
    }
    let now = chrono::Utc::now().timestamp();
    let created_at = message.created_at as i64;
    if created_at > now.saturating_add(MAX_MAILBOX_CLOCK_SKEW_SECS) {
        anyhow::bail!("Mailbox message timestamp is too far in the future");
    }
    let ttl_secs = effective_ttl_secs(message.ttl_ms) as i64;
    if created_at < now.saturating_sub(ttl_secs.saturating_add(MAX_MAILBOX_CLOCK_SKEW_SECS)) {
        anyhow::bail!("Mailbox message is already expired");
    }
    Ok(())
}

fn auth_digest(auth_token_b64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"Qypha-Mailbox-Auth-v1");
    hasher.update(auth_token_b64.as_bytes());
    hex::encode(hasher.finalize())
}

fn access_digest(access_key_b64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"Qypha-Mailbox-Access-v1");
    hasher.update(access_key_b64.as_bytes());
    hex::encode(hasher.finalize())
}

fn effective_ttl_secs(ttl_ms: u64) -> u64 {
    let effective_ttl_ms = if ttl_ms == 0 {
        DEFAULT_MAILBOX_RETENTION_MS
    } else {
        ttl_ms.min(MAX_MAILBOX_RETENTION_MS)
    };
    (effective_ttl_ms.saturating_add(999) / 1000).max(1)
}

fn clamp_expiry(ttl_ms: u64, max_retention_override_ms: Option<u64>) -> u64 {
    let now = chrono::Utc::now().timestamp() as u64;
    let ttl_secs = effective_ttl_secs(match max_retention_override_ms {
        Some(limit) => {
            if ttl_ms == 0 {
                limit
            } else {
                ttl_ms.min(limit)
            }
        }
        None => ttl_ms,
    });
    now.saturating_add(ttl_secs)
}

fn json_error(
    status: StatusCode,
    error: impl Into<String>,
) -> (StatusCode, Json<MailboxErrorResponse>) {
    (
        status,
        Json(MailboxErrorResponse {
            error: error.into(),
        }),
    )
}

async fn health() -> impl IntoResponse {
    Json(MailboxInfoResponse {
        service: "qypha-mailbox",
        version: 1,
    })
}

async fn post_message(
    State(state): State<MailboxServiceState>,
    Json(request): Json<MailboxPostApiRequest>,
) -> impl IntoResponse {
    match state.store.post(request).await {
        Ok(receipt) => (StatusCode::OK, Json(receipt)).into_response(),
        Err(e) => {
            let status = if is_mailbox_throttle_error(&e.to_string()) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            json_error(status, e.to_string()).into_response()
        }
    }
}

async fn poll_messages(
    State(state): State<MailboxServiceState>,
    Json(request): Json<MailboxPollApiRequest>,
) -> impl IntoResponse {
    match state.store.poll(request).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => {
            let status = if is_mailbox_throttle_error(&e.to_string()) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            json_error(status, e.to_string()).into_response()
        }
    }
}

async fn ack_messages(
    State(state): State<MailboxServiceState>,
    Json(request): Json<MailboxAckApiRequest>,
) -> impl IntoResponse {
    match state.store.ack(request).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let status = if is_mailbox_throttle_error(&e.to_string()) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            json_error(status, e.to_string()).into_response()
        }
    }
}

async fn post_contact_message(
    State(state): State<MailboxServiceState>,
    Json(request): Json<ContactMailboxPostRequest>,
) -> impl IntoResponse {
    match state.contact_store.post(request).await {
        Ok(envelope_id) => (
            StatusCode::OK,
            Json(serde_json::json!({ "envelope_id": envelope_id })),
        )
            .into_response(),
        Err(e) => {
            let status = if is_mailbox_throttle_error(&e.to_string()) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            json_error(status, e.to_string()).into_response()
        }
    }
}

async fn poll_contact_messages(
    State(state): State<MailboxServiceState>,
    Json(request): Json<ContactMailboxPollRequest>,
) -> impl IntoResponse {
    match state.contact_store.poll(request).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => {
            let status = if is_mailbox_throttle_error(&e.to_string()) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            json_error(status, e.to_string()).into_response()
        }
    }
}

async fn ack_contact_messages(
    State(state): State<MailboxServiceState>,
    Json(request): Json<ContactMailboxAckRequest>,
) -> impl IntoResponse {
    match state.contact_store.ack(request).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let status = if is_mailbox_throttle_error(&e.to_string()) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            json_error(status, e.to_string()).into_response()
        }
    }
}

async fn put_contact_bundle(
    State(state): State<MailboxServiceState>,
    Json(request): Json<ContactBundlePutRequest>,
) -> impl IntoResponse {
    match state.contact_bundle_store.put(request).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn get_contact_bundle(
    State(state): State<MailboxServiceState>,
    Json(request): Json<ContactBundleGetRequest>,
) -> impl IntoResponse {
    match state.contact_bundle_store.get(request).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn put_group_invite_bundle(
    State(state): State<MailboxServiceState>,
    Json(request): Json<GroupInviteBundlePutRequest>,
) -> impl IntoResponse {
    match state.group_invite_bundle_store.put(request).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn get_group_invite_bundle(
    State(state): State<MailboxServiceState>,
    Json(request): Json<GroupInviteBundleGetRequest>,
) -> impl IntoResponse {
    match state.group_invite_bundle_store.get(request).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

fn build_router(state: MailboxServiceState, max_payload_bytes: usize) -> Router {
    Router::new()
        .route("/healthz", get(health).post(health))
        .route("/v1/mailbox/post", post(post_message))
        .route("/v1/mailbox/poll", post(poll_messages))
        .route("/v1/mailbox/ack", post(ack_messages))
        .route("/v1/contact/post", post(post_contact_message))
        .route("/v1/contact/poll", post(poll_contact_messages))
        .route("/v1/contact/ack", post(ack_contact_messages))
        .route("/v1/contact-bundle/put", post(put_contact_bundle))
        .route("/v1/contact-bundle/get", post(get_contact_bundle))
        .route("/v1/group-invite-bundle/put", post(put_group_invite_bundle))
        .route("/v1/group-invite-bundle/get", post(get_group_invite_bundle))
        .layer(axum::extract::DefaultBodyLimit::max(
            max_payload_bytes.saturating_add(32 * 1024),
        ))
        .with_state(state)
}

fn is_mailbox_throttle_error(error: &str) -> bool {
    error.contains("rate limit")
        || error.contains("quota")
        || error.contains("budget")
        || error.contains("backlog full")
}

pub struct MailboxServiceHandle {
    endpoint: String,
    #[allow(dead_code)]
    listen_port: u16,
    #[allow(dead_code)]
    tor_manager: TorManager,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl MailboxServiceHandle {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub fn shutdown(self) {
        self.task.abort();
    }
}

async fn launch_mailbox_service_background(
    listener: TcpListener,
    actual_port: u16,
    tor_data_dir: &Path,
    circuit_timeout_secs: u64,
    max_payload_bytes: usize,
    store: MailboxStore,
    contact_store: ContactMailboxStore,
    contact_bundle_store: ContactBundleStore,
    group_invite_bundle_store: GroupInviteBundleStore,
) -> Result<MailboxServiceHandle> {
    let tor_manager = TorManager::bootstrap(
        tor_data_dir,
        actual_port,
        circuit_timeout_secs,
        TorServiceRole::Mailbox,
    )
    .await?;
    let endpoint = format!("tor://{}:{}", tor_manager.onion_address(), actual_port);
    let state = MailboxServiceState {
        store: Arc::new(store),
        contact_store: Arc::new(contact_store),
        contact_bundle_store: Arc::new(contact_bundle_store),
        group_invite_bundle_store: Arc::new(group_invite_bundle_store),
    };
    let task = tokio::spawn(async move {
        axum::serve(listener, build_router(state, max_payload_bytes))
            .await
            .context("Mailbox HTTP server exited unexpectedly")
    });
    Ok(MailboxServiceHandle {
        endpoint,
        listen_port: actual_port,
        tor_manager,
        task,
    })
}

pub async fn start_mailbox_service_background(
    data_dir: &Path,
    listen_port: u16,
    tor_data_dir: Option<&Path>,
    circuit_timeout_secs: u64,
    max_payload_bytes: usize,
    relay_policy: MailboxRelayPolicy,
) -> Result<MailboxServiceHandle> {
    let relay_policy = relay_policy.normalized();
    relay_policy.validate()?;
    let listener = TcpListener::bind(("127.0.0.1", listen_port))
        .await
        .with_context(|| format!("Failed to bind mailbox service on 127.0.0.1:{listen_port}"))?;
    let actual_port = listener
        .local_addr()
        .context("Failed to read mailbox listener address")?
        .port();
    let tor_dir = tor_data_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| data_dir.join("tor"));
    let store =
        MailboxStore::open(&data_dir.join("store"), max_payload_bytes, relay_policy).await?;
    let contact_store = ContactMailboxStore::open(&data_dir.join("contact-store")).await?;
    let contact_bundle_store = ContactBundleStore::open(&data_dir.join("contact-bundles")).await?;
    let group_invite_bundle_store =
        GroupInviteBundleStore::open(&data_dir.join("group-invite-bundles")).await?;
    launch_mailbox_service_background(
        listener,
        actual_port,
        &tor_dir,
        circuit_timeout_secs,
        max_payload_bytes,
        store,
        contact_store,
        contact_bundle_store,
        group_invite_bundle_store,
    )
    .await
}

pub async fn start_memory_mailbox_service_background(
    listen_port: u16,
    tor_data_dir: &Path,
    circuit_timeout_secs: u64,
    max_payload_bytes: usize,
    max_retention_ms: u64,
    relay_policy: MailboxRelayPolicy,
) -> Result<MailboxServiceHandle> {
    let relay_policy = relay_policy.normalized();
    relay_policy.validate()?;
    let listener = TcpListener::bind(("127.0.0.1", listen_port))
        .await
        .with_context(|| format!("Failed to bind mailbox service on 127.0.0.1:{listen_port}"))?;
    let actual_port = listener
        .local_addr()
        .context("Failed to read mailbox listener address")?
        .port();
    let store = MailboxStore::open_memory(max_payload_bytes, max_retention_ms, relay_policy);
    let contact_store = ContactMailboxStore::open_memory();
    let contact_bundle_store = ContactBundleStore::open_memory();
    let group_invite_bundle_store = GroupInviteBundleStore::open_memory();
    launch_mailbox_service_background(
        listener,
        actual_port,
        tor_data_dir,
        circuit_timeout_secs,
        max_payload_bytes,
        store,
        contact_store,
        contact_bundle_store,
        group_invite_bundle_store,
    )
    .await
}

pub async fn run_mailbox_service(
    data_dir: &Path,
    listen_port: u16,
    tor_data_dir: Option<&Path>,
    circuit_timeout_secs: u64,
    max_payload_bytes: usize,
    relay_policy: MailboxRelayPolicy,
) -> Result<()> {
    let relay_policy = relay_policy.normalized();
    relay_policy.validate()?;
    let handle = start_mailbox_service_background(
        data_dir,
        listen_port,
        tor_data_dir,
        circuit_timeout_secs,
        max_payload_bytes,
        relay_policy,
    )
    .await?;
    println!("Mailbox endpoint: {}", handle.endpoint());
    println!("Mailbox data dir: {}", data_dir.display().to_string());
    handle
        .task
        .await
        .context("Mailbox HTTP task join failed")??;
    Ok(())
}

#[cfg(test)]
pub async fn spawn_loopback_mailbox_service(
    data_dir: PathBuf,
    max_payload_bytes: usize,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let state = MailboxServiceState {
        store: Arc::new(
            MailboxStore::open(
                &data_dir.join("store"),
                max_payload_bytes,
                MailboxRelayPolicy::default(),
            )
            .await?,
        ),
        contact_store: Arc::new(ContactMailboxStore::open(&data_dir.join("contact-store")).await?),
        contact_bundle_store: Arc::new(
            ContactBundleStore::open(&data_dir.join("contact-bundles")).await?,
        ),
        group_invite_bundle_store: Arc::new(
            GroupInviteBundleStore::open(&data_dir.join("group-invite-bundles")).await?,
        ),
    };
    let handle = tokio::spawn(async move {
        axum::serve(listener, build_router(state, max_payload_bytes))
            .await
            .expect("loopback mailbox service should stay alive for test");
    });
    Ok((addr, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::mailbox_bootstrap::{
        issue_mailbox_bootstrap_token, issue_mailbox_bootstrap_token_with_difficulty,
    };
    use crate::network::protocol::{
        GroupMailboxMessage, GroupMailboxMessageKind, MailboxBootstrapScopeKind,
        MailboxBootstrapToken, MailboxCapability,
    };
    use proptest::prelude::*;

    fn sample_auth_token(fill: u8) -> String {
        BASE64_URL_SAFE_NO_PAD.encode([fill; 32])
    }

    fn sample_access_key(fill: u8) -> String {
        BASE64_URL_SAFE_NO_PAD.encode([fill; 32])
    }

    fn sample_message(message_id: &str, group_id: &str) -> GroupMailboxMessage {
        let created_at_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        GroupMailboxMessage {
            version: 1,
            message_id: message_id.to_string(),
            group_id: group_id.to_string(),
            anonymous_group: true,
            sender_member_id: None,
            kind: GroupMailboxMessageKind::Chat,
            created_at: created_at_ms / 1000,
            created_at_ms,
            ttl_ms: 60_000,
            ciphertext: vec![1, 2, 3],
        }
    }

    fn sample_bootstrap_token_with_options(
        namespace: &str,
        capability_id: &str,
        access_key_b64: &str,
        auth_token_b64: &str,
        scope_id: &str,
        signing_key: Option<&ed25519_dalek::SigningKey>,
        pow_difficulty_bits: Option<u8>,
    ) -> MailboxBootstrapToken {
        let owned_signing_key;
        let signing_key = match signing_key {
            Some(signing_key) => signing_key,
            None => {
                owned_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
                &owned_signing_key
            }
        };
        let capability = MailboxCapability {
            capability_id: capability_id.to_string(),
            access_key_b64: access_key_b64.to_string(),
            auth_token_b64: auth_token_b64.to_string(),
            bootstrap_token: None,
        };
        match pow_difficulty_bits {
            Some(pow_difficulty_bits) => issue_mailbox_bootstrap_token_with_difficulty(
                signing_key,
                MailboxBootstrapScopeKind::Invite,
                scope_id,
                namespace,
                &capability,
                chrono::Utc::now().timestamp().max(0) as u64 + 3_600,
                pow_difficulty_bits,
            )
            .unwrap(),
            None => issue_mailbox_bootstrap_token(
                signing_key,
                MailboxBootstrapScopeKind::Invite,
                scope_id,
                namespace,
                &capability,
                chrono::Utc::now().timestamp().max(0) as u64 + 3_600,
            )
            .unwrap(),
        }
    }

    fn sample_bootstrap_token(
        namespace: &str,
        capability_id: &str,
        access_key_b64: &str,
        auth_token_b64: &str,
        scope_id: &str,
    ) -> MailboxBootstrapToken {
        sample_bootstrap_token_with_options(
            namespace,
            capability_id,
            access_key_b64,
            auth_token_b64,
            scope_id,
            None,
            None,
        )
    }

    #[tokio::test]
    async fn memory_store_tail_cursor_skips_existing_backlog() {
        let store = MailboxStore::open_memory(64 * 1024, 15_000, MailboxRelayPolicy::default());
        let namespace = "mailbox:grp_tail";
        let capability_id = "cap_tail";
        let access_key_b64 = sample_access_key(11);
        let auth_token_b64 = sample_auth_token(1);
        let bootstrap_token = sample_bootstrap_token(
            namespace,
            capability_id,
            &access_key_b64,
            &auth_token_b64,
            "scope_tail",
        );

        store
            .post(MailboxPostApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64.clone(),
                bootstrap_token: Some(bootstrap_token.clone()),
                message: sample_message("msg_1", "grp_tail"),
            })
            .await
            .unwrap();
        store
            .post(MailboxPostApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64.clone(),
                bootstrap_token: Some(bootstrap_token.clone()),
                message: sample_message("msg_2", "grp_tail"),
            })
            .await
            .unwrap();

        let primed = store
            .poll(MailboxPollApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64.clone(),
                bootstrap_token: Some(bootstrap_token.clone()),
                cursor: Some(MAILBOX_CURSOR_TAIL.to_string()),
                limit: 64,
            })
            .await
            .unwrap();
        assert!(primed.items.is_empty());
        assert_eq!(primed.next_cursor.as_deref(), Some("2"));

        let after_tail = store
            .poll(MailboxPollApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64.clone(),
                bootstrap_token: Some(bootstrap_token.clone()),
                cursor: primed.next_cursor,
                limit: 64,
            })
            .await
            .unwrap();
        assert!(after_tail.items.is_empty());
    }

    #[tokio::test]
    async fn sqlite_store_encrypts_payload_json_at_rest() {
        let root = tempfile::tempdir().unwrap();
        let store = MailboxStore::open(
            &root.path().join("store"),
            64 * 1024,
            MailboxRelayPolicy::default(),
        )
        .await
        .unwrap();
        let namespace = "mailbox:grp_sqlite";
        let capability_id = "cap_sqlite";
        let access_key_b64 = sample_access_key(12);
        let auth_token_b64 = sample_auth_token(2);
        let message = sample_message("msg_sqlite", "grp_sqlite");
        let bootstrap_token = sample_bootstrap_token(
            namespace,
            capability_id,
            &access_key_b64,
            &auth_token_b64,
            "scope_sqlite",
        );

        store
            .post(MailboxPostApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64.clone(),
                bootstrap_token: Some(bootstrap_token.clone()),
                message: message.clone(),
            })
            .await
            .unwrap();

        let db_path = root.path().join("store").join("mailbox.sqlite3");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display())).unwrap(),
            )
            .await
            .unwrap();
        let (stored_payload,): (String,) =
            sqlx::query_as("SELECT payload_json FROM mailbox_messages LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(stored_payload.starts_with(MAILBOX_STORE_PAYLOAD_MAGIC));
        assert!(!stored_payload.contains("grp_sqlite"));
        assert!(!stored_payload.contains("msg_sqlite"));

        let polled = store
            .poll(MailboxPollApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64.clone(),
                bootstrap_token: Some(bootstrap_token.clone()),
                cursor: None,
                limit: 64,
            })
            .await
            .unwrap();
        assert_eq!(polled.items.len(), 1);
        assert_eq!(polled.items[0].message, message);
    }

    #[tokio::test]
    async fn sqlite_store_reads_legacy_plaintext_payload_rows() {
        let root = tempfile::tempdir().unwrap();
        let store = MailboxStore::open(
            &root.path().join("store"),
            64 * 1024,
            MailboxRelayPolicy::default(),
        )
        .await
        .unwrap();
        let namespace = "mailbox:grp_legacy";
        let capability_id = "cap_legacy";
        let access_key_b64 = sample_access_key(13);
        let auth_token_b64 = sample_auth_token(3);
        let message = sample_message("msg_legacy", "grp_legacy");
        let bootstrap_token = sample_bootstrap_token(
            namespace,
            capability_id,
            &access_key_b64,
            &auth_token_b64,
            "scope_legacy",
        );

        store
            .authorize(
                namespace,
                capability_id,
                &access_key_b64,
                &auth_token_b64,
                Some(&bootstrap_token),
            )
            .await
            .unwrap();
        let payload_json = serde_json::to_string(&message).unwrap();
        match &store.backend {
            MailboxStoreBackend::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO mailbox_messages
                        (namespace, message_id, created_at, expires_at, payload_json)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .bind(namespace)
                .bind(&message.message_id)
                .bind(message.created_at as i64)
                .bind((chrono::Utc::now().timestamp() + 60) as i64)
                .bind(payload_json)
                .execute(pool)
                .await
                .unwrap();
            }
            MailboxStoreBackend::Memory(_) => unreachable!("sqlite backend expected"),
        }

        let polled = store
            .poll(MailboxPollApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64.clone(),
                bootstrap_token: Some(bootstrap_token.clone()),
                cursor: None,
                limit: 64,
            })
            .await
            .unwrap();
        assert_eq!(polled.items.len(), 1);
        assert_eq!(polled.items[0].message, message);
    }

    #[tokio::test]
    async fn poll_rejects_invalid_cursor_instead_of_replaying_from_zero() {
        let store = MailboxStore::open_memory(64 * 1024, 15_000, MailboxRelayPolicy::default());
        let access_key_b64 = sample_access_key(14);
        let auth_token_b64 = sample_auth_token(4);
        let bootstrap_token = sample_bootstrap_token(
            "mailbox:grp_cursor",
            "cap_cursor",
            &access_key_b64,
            &auth_token_b64,
            "scope_cursor",
        );
        let error = store
            .poll(MailboxPollApiRequest {
                namespace: "mailbox:grp_cursor".to_string(),
                capability_id: "cap_cursor".to_string(),
                access_key_b64,
                auth_token_b64,
                bootstrap_token: Some(bootstrap_token),
                cursor: Some("not-a-number".to_string()),
                limit: 64,
            })
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("Mailbox cursor must be a non-negative integer"));
    }

    #[tokio::test]
    async fn memory_store_rejects_namespace_backlog_growth_past_limit() {
        let store = MailboxStore::open_memory(64 * 1024, 15_000, MailboxRelayPolicy::default());
        let namespace = "mailbox:grp_backlog";
        let capability_id = "cap_backlog";
        let access_key_b64 = sample_access_key(15);
        let auth_token_b64 = sample_auth_token(5);
        let bootstrap_token = sample_bootstrap_token(
            namespace,
            capability_id,
            &access_key_b64,
            &auth_token_b64,
            "scope_backlog",
        );

        for index in 0..MAX_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE {
            store
                .post(MailboxPostApiRequest {
                    namespace: namespace.to_string(),
                    capability_id: capability_id.to_string(),
                    access_key_b64: access_key_b64.clone(),
                    auth_token_b64: auth_token_b64.clone(),
                    bootstrap_token: Some(bootstrap_token.clone()),
                    message: sample_message(&format!("msg_{index}"), "grp_backlog"),
                })
                .await
                .unwrap();
        }

        let error = store
            .post(MailboxPostApiRequest {
                namespace: namespace.to_string(),
                capability_id: capability_id.to_string(),
                access_key_b64: access_key_b64.clone(),
                auth_token_b64: auth_token_b64,
                bootstrap_token: Some(bootstrap_token.clone()),
                message: sample_message("msg_overflow", "grp_backlog"),
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("backlog full"));
    }

    #[tokio::test]
    async fn authorize_rejects_access_key_mismatch_for_existing_namespace() {
        let store = MailboxStore::open_memory(64 * 1024, 15_000, MailboxRelayPolicy::default());
        let namespace = "mailbox:grp_access_guard";
        let access_key_b64 = sample_access_key(31);
        let auth_token_b64 = sample_auth_token(21);
        let bootstrap_token = sample_bootstrap_token(
            namespace,
            "cap_access_guard",
            &access_key_b64,
            &auth_token_b64,
            "scope_access_guard",
        );

        store
            .authorize(
                namespace,
                "cap_access_guard",
                &access_key_b64,
                &auth_token_b64,
                Some(&bootstrap_token),
            )
            .await
            .unwrap();

        let error = store
            .authorize(
                namespace,
                "cap_access_guard",
                &sample_access_key(32),
                &auth_token_b64,
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Mailbox capability rejected"));
    }

    #[tokio::test]
    async fn bootstrap_budget_limits_new_namespace_claims() {
        let store = MailboxStore::open_memory(
            64 * 1024,
            15_000,
            MailboxRelayPolicy {
                bootstrap_budget_per_hour: 2,
                max_active_namespaces: 16,
                ..MailboxRelayPolicy::default()
            },
        );

        for index in 0..2usize {
            let access_key_b64 = sample_access_key(40 + index as u8);
            let auth_token_b64 = sample_auth_token(50 + index as u8);
            let bootstrap_token = sample_bootstrap_token(
                &format!("mailbox:grp_budget_{index}"),
                &format!("cap_budget_{index}"),
                &access_key_b64,
                &auth_token_b64,
                &format!("scope_budget_{index}"),
            );
            store
                .authorize(
                    &format!("mailbox:grp_budget_{index}"),
                    &format!("cap_budget_{index}"),
                    &access_key_b64,
                    &auth_token_b64,
                    Some(&bootstrap_token),
                )
                .await
                .unwrap();
        }

        let access_key_b64 = sample_access_key(60);
        let auth_token_b64 = sample_auth_token(61);
        let bootstrap_token = sample_bootstrap_token(
            "mailbox:grp_budget_overflow",
            "cap_budget_overflow",
            &access_key_b64,
            &auth_token_b64,
            "scope_budget_overflow",
        );
        let error = store
            .authorize(
                "mailbox:grp_budget_overflow",
                "cap_budget_overflow",
                &access_key_b64,
                &auth_token_b64,
                Some(&bootstrap_token),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("bootstrap budget exceeded"));
    }

    #[tokio::test]
    async fn namespace_quota_caps_active_namespace_growth() {
        let store = MailboxStore::open_memory(
            64 * 1024,
            15_000,
            MailboxRelayPolicy {
                bootstrap_budget_per_hour: 8,
                max_active_namespaces: 1,
                ..MailboxRelayPolicy::default()
            },
        );

        let access_key_a = sample_access_key(70);
        let auth_token_a = sample_auth_token(71);
        let bootstrap_token_a = sample_bootstrap_token(
            "mailbox:grp_quota_a",
            "cap_quota_a",
            &access_key_a,
            &auth_token_a,
            "scope_quota_a",
        );
        store
            .authorize(
                "mailbox:grp_quota_a",
                "cap_quota_a",
                &access_key_a,
                &auth_token_a,
                Some(&bootstrap_token_a),
            )
            .await
            .unwrap();

        let access_key_b = sample_access_key(72);
        let auth_token_b = sample_auth_token(73);
        let bootstrap_token_b = sample_bootstrap_token(
            "mailbox:grp_quota_b",
            "cap_quota_b",
            &access_key_b,
            &auth_token_b,
            "scope_quota_b",
        );
        let error = store
            .authorize(
                "mailbox:grp_quota_b",
                "cap_quota_b",
                &access_key_b,
                &auth_token_b,
                Some(&bootstrap_token_b),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("namespace quota exceeded"));
    }

    #[tokio::test]
    async fn authorize_rejects_missing_bootstrap_token_for_new_namespace() {
        let store = MailboxStore::open_memory(64 * 1024, 15_000, MailboxRelayPolicy::default());
        let error = store
            .authorize(
                "mailbox:grp_missing_token",
                "cap_missing_token",
                &sample_access_key(80),
                &sample_auth_token(81),
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("bootstrap token required"));
    }

    #[tokio::test]
    async fn authorize_rejects_tampered_bootstrap_token() {
        let store = MailboxStore::open_memory(64 * 1024, 15_000, MailboxRelayPolicy::default());
        let access_key_b64 = sample_access_key(82);
        let auth_token_b64 = sample_auth_token(83);
        let mut bootstrap_token = sample_bootstrap_token(
            "mailbox:grp_tampered_token",
            "cap_tampered_token",
            &access_key_b64,
            &auth_token_b64,
            "scope_tampered_token",
        );
        bootstrap_token.namespace = "mailbox:grp_other".to_string();

        let error = store
            .authorize(
                "mailbox:grp_tampered_token",
                "cap_tampered_token",
                &access_key_b64,
                &auth_token_b64,
                Some(&bootstrap_token),
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("namespace mismatch")
                || error.to_string().contains("signature verification failed")
        );
    }

    #[tokio::test]
    async fn authorize_rejects_bootstrap_token_below_required_pow_difficulty() {
        let store = MailboxStore::open_memory(
            64 * 1024,
            15_000,
            MailboxRelayPolicy {
                min_bootstrap_pow_difficulty_bits: 12,
                ..MailboxRelayPolicy::default()
            },
        );
        let access_key_b64 = sample_access_key(84);
        let auth_token_b64 = sample_auth_token(85);
        let bootstrap_token = sample_bootstrap_token_with_options(
            "mailbox:grp_low_pow",
            "cap_low_pow",
            &access_key_b64,
            &auth_token_b64,
            "scope_low_pow",
            None,
            Some(4),
        );

        let error = store
            .authorize(
                "mailbox:grp_low_pow",
                "cap_low_pow",
                &access_key_b64,
                &auth_token_b64,
                Some(&bootstrap_token),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("PoW below required difficulty"));
    }

    #[tokio::test]
    async fn authorize_rejects_bootstrap_token_from_non_allowlisted_issuer() {
        let allowed_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let disallowed_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let store = MailboxStore::open_memory(
            64 * 1024,
            15_000,
            MailboxRelayPolicy {
                bootstrap_issuer_allowlist: vec![hex::encode(
                    allowed_signing_key.verifying_key().as_bytes(),
                )],
                ..MailboxRelayPolicy::default()
            },
        );
        let access_key_b64 = sample_access_key(86);
        let auth_token_b64 = sample_auth_token(87);
        let bootstrap_token = sample_bootstrap_token_with_options(
            "mailbox:grp_allowlist",
            "cap_allowlist",
            &access_key_b64,
            &auth_token_b64,
            "scope_allowlist",
            Some(&disallowed_signing_key),
            None,
        );

        let error = store
            .authorize(
                "mailbox:grp_allowlist",
                "cap_allowlist",
                &access_key_b64,
                &auth_token_b64,
                Some(&bootstrap_token),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not allowlisted"));
    }

    proptest! {
        #[test]
        fn invalid_cursor_strings_are_rejected(cursor in ".{1,64}") {
            let trimmed_cursor = cursor.trim();
            prop_assume!(trimmed_cursor != MAILBOX_CURSOR_TAIL);
            prop_assume!(trimmed_cursor.is_empty() || trimmed_cursor.parse::<i64>().is_err());

            let store = MailboxStore::open_memory(64 * 1024, 15_000, MailboxRelayPolicy::default());
            let access_key_b64 = sample_access_key(16);
            let auth_token_b64 = sample_auth_token(6);
            let bootstrap_token = sample_bootstrap_token(
                "mailbox:grp_prop",
                "cap_prop",
                &access_key_b64,
                &auth_token_b64,
                "scope_prop",
            );
            let request = MailboxPollApiRequest {
                namespace: "mailbox:grp_prop".to_string(),
                capability_id: "cap_prop".to_string(),
                access_key_b64,
                auth_token_b64,
                bootstrap_token: Some(bootstrap_token),
                cursor: Some(cursor),
                limit: 64,
            };
            let error = tokio_test::block_on(async { store.poll(request).await.unwrap_err() });
            prop_assert!(error
                .to_string()
                .contains("Mailbox cursor"));
        }
    }
}
