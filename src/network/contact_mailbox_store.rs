use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use crate::network::contact_mailbox::{
    ContactMailboxAckRequest, ContactMailboxItem, ContactMailboxPollRequest,
    ContactMailboxPollResult, ContactMailboxPostRequest,
};

const DEFAULT_CONTACT_MAILBOX_RETENTION_SECS: i64 = 24 * 60 * 60;
const MAX_CONTACT_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE: usize = 256;
const MAX_CONTACT_MAILBOX_POSTS_PER_MINUTE: usize = 120;
const MAX_CONTACT_MAILBOX_POLLS_PER_MINUTE: usize = 360;
const MAX_CONTACT_MAILBOX_ACKS_PER_MINUTE: usize = 720;
const MAX_CONTACT_MAILBOX_CURSOR_LEN: usize = 32;

pub struct ContactMailboxStore {
    backend: ContactMailboxStoreBackend,
    rate_limiter: ContactMailboxRateLimiter,
}

enum ContactMailboxStoreBackend {
    Sqlite(SqlitePool),
    Memory(Mutex<MemoryContactMailboxState>),
}

#[derive(Default)]
struct MemoryContactMailboxState {
    inboxes: HashMap<String, MemoryContactMailboxInbox>,
}

#[derive(Default)]
struct MemoryContactMailboxInbox {
    next_seq: i64,
    messages: VecDeque<MemoryContactMailboxMessage>,
}

struct MemoryContactMailboxMessage {
    seq: i64,
    recipient_did: String,
    mailbox_namespace: String,
    sender_did: String,
    created_at: i64,
    expires_at: i64,
    payload_json: String,
}

struct ContactMailboxRateLimiter {
    buckets: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl ContactMailboxStore {
    pub async fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let db_path = data_dir.join("contact-mailbox.sqlite3");
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .context("Invalid contact mailbox sqlite path")?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .context("Failed to open contact mailbox sqlite database")?;

        sqlx::query("PRAGMA journal_mode=WAL;")
            .execute(&pool)
            .await
            .ok();
        sqlx::query("PRAGMA foreign_keys=ON;")
            .execute(&pool)
            .await
            .ok();

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS contact_mailbox_messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_did TEXT NOT NULL,
                mailbox_namespace TEXT NOT NULL,
                sender_did TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_contact_mailbox_namespace_seq
             ON contact_mailbox_messages(mailbox_namespace, seq)",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_contact_mailbox_expiry
             ON contact_mailbox_messages(expires_at)",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            backend: ContactMailboxStoreBackend::Sqlite(pool),
            rate_limiter: ContactMailboxRateLimiter::default(),
        })
    }

    pub fn open_memory() -> Self {
        Self {
            backend: ContactMailboxStoreBackend::Memory(Mutex::new(
                MemoryContactMailboxState::default(),
            )),
            rate_limiter: ContactMailboxRateLimiter::default(),
        }
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        match &self.backend {
            ContactMailboxStoreBackend::Sqlite(pool) => {
                sqlx::query("DELETE FROM contact_mailbox_messages WHERE expires_at <= ?1")
                    .bind(now)
                    .execute(pool)
                    .await?;
            }
            ContactMailboxStoreBackend::Memory(state) => {
                let mut state = state.lock().await;
                for inbox in state.inboxes.values_mut() {
                    inbox.messages.retain(|message| message.expires_at > now);
                }
                state.inboxes.retain(|_, inbox| !inbox.messages.is_empty());
            }
        }
        Ok(())
    }

    pub async fn post(&self, request: ContactMailboxPostRequest) -> Result<String> {
        request.validate()?;
        self.rate_limiter
            .check(
                format!(
                    "post:{}:{}:{}",
                    request.mailbox_namespace, request.recipient_did, request.sender_did
                ),
                MAX_CONTACT_MAILBOX_POSTS_PER_MINUTE,
                60,
            )
            .await?;
        self.cleanup_expired().await?;

        let payload_json =
            serde_json::to_string(&request).context("Failed to encode contact mailbox payload")?;
        let expires_at = request.created_at as i64 + DEFAULT_CONTACT_MAILBOX_RETENTION_SECS;

        match &self.backend {
            ContactMailboxStoreBackend::Sqlite(pool) => {
                let pending = sqlx::query_as::<_, (i64,)>(
                    "SELECT COUNT(*) FROM contact_mailbox_messages
                     WHERE mailbox_namespace = ?1",
                )
                .bind(&request.mailbox_namespace)
                .fetch_one(pool)
                .await?
                .0
                .max(0) as usize;
                if pending >= MAX_CONTACT_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE {
                    anyhow::bail!(
                        "Contact mailbox backlog full: {} pending messages exceeds limit of {}",
                        pending,
                        MAX_CONTACT_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE
                    );
                }

                let result = sqlx::query(
                    "INSERT INTO contact_mailbox_messages
                        (recipient_did, mailbox_namespace, sender_did, created_at, expires_at, payload_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&request.recipient_did)
                .bind(&request.mailbox_namespace)
                .bind(&request.sender_did)
                .bind(request.created_at as i64)
                .bind(expires_at)
                .bind(payload_json)
                .execute(pool)
                .await?;
                Ok(result.last_insert_rowid().to_string())
            }
            ContactMailboxStoreBackend::Memory(state) => {
                let mut state = state.lock().await;
                let inbox = state
                    .inboxes
                    .entry(request.mailbox_namespace.clone())
                    .or_insert_with(|| MemoryContactMailboxInbox {
                        next_seq: 1,
                        messages: VecDeque::new(),
                    });
                if inbox.messages.len() >= MAX_CONTACT_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE {
                    anyhow::bail!(
                        "Contact mailbox backlog full: {} pending messages exceeds limit of {}",
                        inbox.messages.len(),
                        MAX_CONTACT_MAILBOX_PENDING_MESSAGES_PER_NAMESPACE
                    );
                }
                let seq = inbox.next_seq;
                inbox.next_seq = inbox.next_seq.saturating_add(1);
                inbox.messages.push_back(MemoryContactMailboxMessage {
                    seq,
                    recipient_did: request.recipient_did,
                    mailbox_namespace: request.mailbox_namespace,
                    sender_did: request.sender_did,
                    created_at: request.created_at as i64,
                    expires_at,
                    payload_json,
                });
                Ok(seq.to_string())
            }
        }
    }

    pub async fn poll(
        &self,
        request: ContactMailboxPollRequest,
    ) -> Result<ContactMailboxPollResult> {
        request.validate()?;
        self.rate_limiter
            .check(
                format!(
                    "poll:{}:{}",
                    request.mailbox_namespace, request.recipient_did
                ),
                MAX_CONTACT_MAILBOX_POLLS_PER_MINUTE,
                60,
            )
            .await?;
        self.cleanup_expired().await?;

        let cursor = parse_cursor(request.cursor.as_deref())?;
        match &self.backend {
            ContactMailboxStoreBackend::Sqlite(pool) => {
                let rows = sqlx::query_as::<_, (i64, String)>(
                    "SELECT seq, payload_json
                     FROM contact_mailbox_messages
                     WHERE mailbox_namespace = ?1
                       AND recipient_did = ?2
                       AND seq > ?3
                     ORDER BY seq ASC
                     LIMIT 128",
                )
                .bind(&request.mailbox_namespace)
                .bind(&request.recipient_did)
                .bind(cursor)
                .fetch_all(pool)
                .await?;

                let mut items = Vec::with_capacity(rows.len());
                let mut next_cursor = request.cursor.clone();
                for (seq, payload_json) in rows {
                    let decoded: ContactMailboxPostRequest = serde_json::from_str(&payload_json)
                        .context("Failed to decode stored contact mailbox payload")?;
                    next_cursor = Some(seq.to_string());
                    items.push(ContactMailboxItem {
                        envelope_id: seq.to_string(),
                        sender_did: decoded.sender_did,
                        request: decoded.request,
                    });
                }
                Ok(ContactMailboxPollResult { items, next_cursor })
            }
            ContactMailboxStoreBackend::Memory(state) => {
                let state = state.lock().await;
                let Some(inbox) = state.inboxes.get(&request.mailbox_namespace) else {
                    return Ok(ContactMailboxPollResult {
                        items: Vec::new(),
                        next_cursor: request.cursor,
                    });
                };
                let mut items = Vec::new();
                let mut next_cursor = request.cursor.clone();
                for message in inbox.messages.iter().filter(|message| {
                    message.seq > cursor
                        && message.recipient_did == request.recipient_did
                        && message.mailbox_namespace == request.mailbox_namespace
                }) {
                    let decoded: ContactMailboxPostRequest =
                        serde_json::from_str(&message.payload_json)
                            .context("Failed to decode stored contact mailbox payload")?;
                    next_cursor = Some(message.seq.to_string());
                    items.push(ContactMailboxItem {
                        envelope_id: message.seq.to_string(),
                        sender_did: message.sender_did.clone(),
                        request: decoded.request,
                    });
                }
                Ok(ContactMailboxPollResult { items, next_cursor })
            }
        }
    }

    pub async fn ack(&self, request: ContactMailboxAckRequest) -> Result<()> {
        request.validate()?;
        self.rate_limiter
            .check(
                format!(
                    "ack:{}:{}",
                    request.mailbox_namespace, request.recipient_did
                ),
                MAX_CONTACT_MAILBOX_ACKS_PER_MINUTE,
                60,
            )
            .await?;
        for envelope_id in &request.envelope_ids {
            validate_envelope_id(envelope_id)?;
        }

        match &self.backend {
            ContactMailboxStoreBackend::Sqlite(pool) => {
                for envelope_id in &request.envelope_ids {
                    sqlx::query(
                        "DELETE FROM contact_mailbox_messages
                         WHERE mailbox_namespace = ?1
                           AND recipient_did = ?2
                           AND seq = ?3",
                    )
                    .bind(&request.mailbox_namespace)
                    .bind(&request.recipient_did)
                    .bind(envelope_id.parse::<i64>().unwrap_or_default())
                    .execute(pool)
                    .await?;
                }
            }
            ContactMailboxStoreBackend::Memory(state) => {
                let mut state = state.lock().await;
                if let Some(inbox) = state.inboxes.get_mut(&request.mailbox_namespace) {
                    inbox.messages.retain(|message| {
                        message.recipient_did != request.recipient_did
                            || !request
                                .envelope_ids
                                .iter()
                                .any(|id| id == &message.seq.to_string())
                    });
                }
            }
        }
        Ok(())
    }
}

impl Default for ContactMailboxRateLimiter {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }
}

impl ContactMailboxRateLimiter {
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
            anyhow::bail!("Contact mailbox rate limit exceeded");
        }
        bucket.push_back(now);
        Ok(())
    }
}

fn parse_cursor(cursor: Option<&str>) -> Result<i64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let cursor = cursor.trim();
    if cursor.is_empty() {
        anyhow::bail!("Contact mailbox cursor must not be blank");
    }
    if cursor.len() > MAX_CONTACT_MAILBOX_CURSOR_LEN {
        anyhow::bail!(
            "Contact mailbox cursor too long: {} bytes exceeds limit of {}",
            cursor.len(),
            MAX_CONTACT_MAILBOX_CURSOR_LEN
        );
    }
    if !cursor.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("Contact mailbox cursor must be numeric");
    }
    cursor
        .parse::<i64>()
        .context("Contact mailbox cursor must be numeric")
}

fn validate_envelope_id(envelope_id: &str) -> Result<()> {
    if envelope_id.is_empty() || envelope_id.len() > MAX_CONTACT_MAILBOX_CURSOR_LEN {
        anyhow::bail!("Contact mailbox envelope id must be present and bounded");
    }
    if !envelope_id.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("Contact mailbox envelope id must be numeric");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_mailbox::{
        build_contact_mailbox_post_request, ContactMailboxAckRequest, ContactMailboxPollRequest,
    };
    use crate::network::contact_request::build_contact_request_agent_request;
    use crate::network::did_profile::{DidContactService, DidProfile};
    use crate::network::direct_invite_token::DirectInviteTransportPolicy;
    use serde_json::json;

    fn test_config_for(did: &str, name: &str) -> AppConfig {
        serde_json::from_value(json!({
            "agent": {
                "name": name,
                "role": "agent",
                "did": did
            },
            "network": {
                "listen_port": 9090,
                "bootstrap_nodes": [],
                "enable_mdns": false,
                "enable_kademlia": false,
                "transport_mode": "tor"
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

    fn tor_profile_for(keypair: &AgentKeyPair) -> DidProfile {
        DidProfile::generate(
            keypair,
            vec![DidContactService::TorMailbox {
                onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
                    .to_string(),
                mailbox_namespace: "contact:test".to_string(),
                port: 9444,
            }],
            None,
        )
    }

    #[tokio::test]
    async fn memory_store_roundtrip_post_poll_ack() {
        let store = ContactMailboxStore::open_memory();
        let sender = AgentKeyPair::generate("sender", "agent");
        let recipient = AgentKeyPair::generate("recipient", "agent");
        let sender_config = test_config_for(&sender.did, "sender");
        let request = build_contact_request_agent_request(
            &sender_config,
            &sender.signing_key,
            &sender,
            tor_profile_for(&sender),
            &tor_profile_for(&recipient),
            Some("hello".to_string()),
            None,
            DirectInviteTransportPolicy::TorOnly,
        )
        .unwrap();
        let post = build_contact_mailbox_post_request(
            recipient.did.clone(),
            "contact:test".to_string(),
            hex::encode(sender.verifying_key.as_bytes()),
            request,
        );

        let envelope_id = store.post(post).await.unwrap();
        let poll = ContactMailboxPollRequest::sign(
            recipient.did.clone(),
            "contact:test".to_string(),
            None,
            &recipient.signing_key,
        );
        let polled = store.poll(poll).await.unwrap();
        assert_eq!(polled.items.len(), 1);
        assert_eq!(polled.items[0].sender_did, sender.did);

        let ack = ContactMailboxAckRequest::sign(
            recipient.did.clone(),
            "contact:test".to_string(),
            vec![envelope_id],
            &recipient.signing_key,
        );
        store.ack(ack).await.unwrap();
        let repoll = ContactMailboxPollRequest::sign(
            recipient.did.clone(),
            "contact:test".to_string(),
            None,
            &recipient.signing_key,
        );
        assert!(store.poll(repoll).await.unwrap().items.is_empty());
    }
}
