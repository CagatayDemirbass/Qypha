use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::protocol::{
    GroupMailboxMessage, MailboxBootstrapToken, MailboxCapability, MailboxDescriptor,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxPostReceipt {
    pub message_id: String,
    #[serde(default)]
    pub server_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxPollRequest {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default = "default_poll_limit")]
    pub limit: usize,
}

fn default_poll_limit() -> usize {
    64
}

pub const MAILBOX_CURSOR_TAIL: &str = "$tail";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxPollItem {
    pub envelope_id: String,
    pub message: GroupMailboxMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxPollResult {
    pub items: Vec<MailboxPollItem>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxPostApiRequest {
    pub namespace: String,
    pub capability_id: String,
    pub access_key_b64: String,
    pub auth_token_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<MailboxBootstrapToken>,
    pub message: GroupMailboxMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxPollApiRequest {
    pub namespace: String,
    pub capability_id: String,
    pub access_key_b64: String,
    pub auth_token_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<MailboxBootstrapToken>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default = "default_poll_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxAckApiRequest {
    pub namespace: String,
    pub capability_id: String,
    pub access_key_b64: String,
    pub auth_token_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<MailboxBootstrapToken>,
    pub envelope_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxErrorResponse {
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxServiceEndpoint {
    Tor { onion: String, port: u16 },
    LoopbackHttp { host: String, port: u16 },
}

pub fn parse_mailbox_service_endpoint(endpoint: &str) -> Result<MailboxServiceEndpoint> {
    let url = endpoint.trim();
    if url.is_empty() {
        anyhow::bail!("Mailbox endpoint must not be empty");
    }
    if let Some(rest) = url.strip_prefix("tor://") {
        let (host, port) = split_host_port(rest)?;
        let onion = host.trim_end_matches(".onion").to_string();
        if onion.len() != 56
            || !onion
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
        {
            anyhow::bail!("Tor mailbox endpoint must contain a valid v3 onion hostname");
        }
        return Ok(MailboxServiceEndpoint::Tor { onion, port });
    }

    if let Some(rest) = url.strip_prefix("http://") {
        let (host, port) = split_host_port(rest)?;
        if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" {
            return Ok(MailboxServiceEndpoint::LoopbackHttp { host, port });
        }
        anyhow::bail!("Clear-net mailbox endpoints are only allowed for loopback testing");
    }

    anyhow::bail!("Unsupported mailbox endpoint scheme; expected tor:// or loopback http://")
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    let value = value.trim_end_matches('/');
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Mailbox endpoint must include a port"))?;
    let host = host.trim().trim_matches('[').trim_matches(']');
    if host.is_empty() {
        anyhow::bail!("Mailbox endpoint host must not be empty");
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("Mailbox endpoint port must be a valid u16"))?;
    Ok((host.to_string(), port))
}

#[async_trait]
pub trait MailboxTransport: Send + Sync {
    async fn post_message(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        message: &GroupMailboxMessage,
    ) -> Result<MailboxPostReceipt>;

    async fn poll_messages(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        request: &MailboxPollRequest,
    ) -> Result<MailboxPollResult>;

    async fn ack_messages(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        envelope_ids: &[String],
    ) -> Result<()>;
}

#[async_trait]
impl<T> MailboxTransport for Arc<T>
where
    T: MailboxTransport + ?Sized,
{
    async fn post_message(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        message: &GroupMailboxMessage,
    ) -> Result<MailboxPostReceipt> {
        (**self).post_message(descriptor, capability, message).await
    }

    async fn poll_messages(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        request: &MailboxPollRequest,
    ) -> Result<MailboxPollResult> {
        (**self)
            .poll_messages(descriptor, capability, request)
            .await
    }

    async fn ack_messages(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        envelope_ids: &[String],
    ) -> Result<()> {
        (**self)
            .ack_messages(descriptor, capability, envelope_ids)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tor_mailbox_endpoint() {
        let endpoint = parse_mailbox_service_endpoint(
            "tor://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9444",
        )
        .unwrap();
        assert_eq!(
            endpoint,
            MailboxServiceEndpoint::Tor {
                onion: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx".to_string(),
                port: 9444,
            }
        );
    }

    #[test]
    fn rejects_non_loopback_http_mailbox_endpoint() {
        assert!(parse_mailbox_service_endpoint("http://example.com:8080").is_err());
    }
}
