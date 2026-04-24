use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arti_client::{TorClient, TorClientConfig};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;

use super::mailbox_transport::{
    parse_mailbox_service_endpoint, MailboxAckApiRequest, MailboxErrorResponse,
    MailboxPollApiRequest, MailboxPollRequest, MailboxPollResult, MailboxPostApiRequest,
    MailboxPostReceipt, MailboxServiceEndpoint, MailboxTransport,
};
use super::protocol::{
    GroupMailboxMessage, MailboxCapability, MailboxDescriptor, MailboxTransportKind,
};

#[derive(Clone)]
pub struct TorMailboxTransport {
    tor_data_dir: Arc<PathBuf>,
    tor_client: Arc<OnceCell<Arc<TorClient<PreferredRuntime>>>>,
}

impl Default for TorMailboxTransport {
    fn default() -> Self {
        Self::new(PathBuf::from(".qypha-mailbox-tor"))
    }
}

impl TorMailboxTransport {
    pub fn new(tor_data_dir: PathBuf) -> Self {
        Self {
            tor_data_dir: Arc::new(tor_data_dir),
            tor_client: Arc::new(OnceCell::new()),
        }
    }

    fn validate_descriptor(descriptor: &MailboxDescriptor) -> Result<()> {
        if descriptor.transport != MailboxTransportKind::Tor {
            bail!("Tor mailbox transport only accepts tor descriptors");
        }
        if descriptor.namespace.trim().is_empty() {
            bail!("Tor mailbox namespace must not be empty");
        }
        if descriptor.poll_interval_ms == 0 {
            bail!("Tor mailbox poll interval must be greater than zero");
        }
        let endpoint = descriptor
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Mailbox descriptor missing service endpoint"))?;
        parse_mailbox_service_endpoint(endpoint)?;
        Ok(())
    }

    fn validate_capability(capability: &MailboxCapability) -> Result<()> {
        if capability.capability_id.trim().is_empty() {
            bail!("Tor mailbox capability id must not be empty");
        }
        if capability.access_key_b64.trim().is_empty() {
            bail!("Tor mailbox access key must not be empty");
        }
        if capability.auth_token_b64.trim().is_empty() {
            bail!("Tor mailbox auth token must not be empty");
        }
        Ok(())
    }

    async fn tor_client(&self) -> Result<Arc<TorClient<PreferredRuntime>>> {
        self.tor_client
            .get_or_try_init(|| async {
                let cache_dir = self.tor_data_dir.join("cache");
                let state_dir = self.tor_data_dir.join("state");
                std::fs::create_dir_all(&cache_dir)?;
                std::fs::create_dir_all(&state_dir)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o700);
                    std::fs::set_permissions(&*self.tor_data_dir, perms.clone())?;
                    std::fs::set_permissions(&cache_dir, perms.clone())?;
                    std::fs::set_permissions(&state_dir, perms)?;
                }

                let mut builder = TorClientConfig::builder();
                {
                    use arti_client::config::CfgPath;
                    let storage = builder.storage();
                    storage.cache_dir(CfgPath::new_literal(cache_dir));
                    storage.state_dir(CfgPath::new_literal(state_dir));
                }
                let config = builder
                    .build()
                    .context("Failed to build mailbox Tor client config")?;
                let client = TorClient::create_bootstrapped(config)
                    .await
                    .context("Failed to bootstrap mailbox Tor client")?;
                Ok::<_, anyhow::Error>(Arc::new(client))
            })
            .await
            .cloned()
    }

    async fn send_request<TReq, TRes>(
        &self,
        descriptor: &MailboxDescriptor,
        path: &str,
        request: &TReq,
    ) -> Result<TRes>
    where
        TReq: serde::Serialize,
        TRes: serde::de::DeserializeOwned,
    {
        Self::validate_descriptor(descriptor)?;
        let endpoint = parse_mailbox_service_endpoint(
            descriptor
                .endpoint
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Mailbox descriptor missing service endpoint"))?,
        )?;
        match endpoint {
            MailboxServiceEndpoint::Tor { onion, port } => {
                let client = self.tor_client().await?;
                let stream = client
                    .connect((format!("{}.onion", onion), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to Tor mailbox {onion}.onion:{port}")
                    })?;
                send_json_over_stream(stream, &format!("{}.onion", onion), path, request).await
            }
            MailboxServiceEndpoint::LoopbackHttp { host, port } => {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to loopback mailbox {host}:{port}")
                    })?;
                send_json_over_stream(stream, &host, path, request).await
            }
        }
    }

    async fn send_empty_ok<TReq>(
        &self,
        descriptor: &MailboxDescriptor,
        path: &str,
        request: &TReq,
    ) -> Result<()>
    where
        TReq: serde::Serialize,
    {
        Self::validate_descriptor(descriptor)?;
        let endpoint = parse_mailbox_service_endpoint(
            descriptor
                .endpoint
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Mailbox descriptor missing service endpoint"))?,
        )?;
        match endpoint {
            MailboxServiceEndpoint::Tor { onion, port } => {
                let client = self.tor_client().await?;
                let stream = client
                    .connect((format!("{}.onion", onion), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to Tor mailbox {onion}.onion:{port}")
                    })?;
                send_empty_over_stream(stream, &format!("{}.onion", onion), path, request).await
            }
            MailboxServiceEndpoint::LoopbackHttp { host, port } => {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to loopback mailbox {host}:{port}")
                    })?;
                send_empty_over_stream(stream, &host, path, request).await
            }
        }
    }
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    })
}

fn parse_status_code(status_line: &str) -> Result<u16> {
    let mut parts = status_line.split_whitespace();
    let http = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response"))?;
    if !http.starts_with("HTTP/1.") {
        bail!("Unsupported HTTP version");
    }
    let status = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing HTTP status code"))?;
    status
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("Invalid HTTP status code"))
}

async fn read_http_response<S>(mut stream: S) -> Result<(u16, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(4096);
    let mut temp = [0u8; 2048];
    let header_end;
    loop {
        let read = stream.read(&mut temp).await?;
        if read == 0 {
            bail!("Mailbox HTTP response ended before headers");
        }
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }

    let header_bytes = &buffer[..header_end];
    let header_text = std::str::from_utf8(header_bytes)
        .context("Mailbox HTTP response headers are not valid UTF-8")?;
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Mailbox HTTP response missing status line"))?;
    let status = parse_status_code(status_line)?;
    let headers_only = &header_text[status_line.len()..];
    let content_length = parse_content_length(headers_only).unwrap_or(0);

    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut temp).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);
    }

    let body = if content_length == 0 {
        buffer[header_end..].to_vec()
    } else {
        buffer[header_end..header_end + content_length.min(buffer.len().saturating_sub(header_end))]
            .to_vec()
    };
    Ok((status, body))
}

async fn send_json_over_stream<S, TReq, TRes>(
    mut stream: S,
    host: &str,
    path: &str,
    request: &TReq,
) -> Result<TRes>
where
    S: AsyncRead + AsyncWrite + Unpin,
    TReq: serde::Serialize,
    TRes: serde::de::DeserializeOwned,
{
    let body = serde_json::to_vec(request).context("Failed to encode mailbox HTTP request")?;
    let request_bytes = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        body.len()
    );
    stream.write_all(request_bytes.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let (status, response_body) = read_http_response(stream).await?;
    if !(200..300).contains(&status) {
        if let Ok(error) = serde_json::from_slice::<MailboxErrorResponse>(&response_body) {
            bail!("{}", error.error);
        }
        bail!(
            "Mailbox HTTP request failed with status {} and body {}",
            status,
            String::from_utf8_lossy(&response_body)
        );
    }
    serde_json::from_slice(&response_body).context("Failed to decode mailbox HTTP response")
}

async fn send_empty_over_stream<S, TReq>(
    mut stream: S,
    host: &str,
    path: &str,
    request: &TReq,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    TReq: serde::Serialize,
{
    let body = serde_json::to_vec(request).context("Failed to encode mailbox HTTP request")?;
    let request_bytes = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        body.len()
    );
    stream.write_all(request_bytes.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let (status, response_body) = read_http_response(stream).await?;
    if status == 204 || status == 200 {
        return Ok(());
    }
    if let Ok(error) = serde_json::from_slice::<MailboxErrorResponse>(&response_body) {
        bail!("{}", error.error);
    }
    bail!(
        "Mailbox HTTP request failed with status {} and body {}",
        status,
        String::from_utf8_lossy(&response_body)
    );
}

#[async_trait]
impl MailboxTransport for TorMailboxTransport {
    async fn post_message(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        message: &GroupMailboxMessage,
    ) -> Result<MailboxPostReceipt> {
        Self::validate_descriptor(descriptor)?;
        Self::validate_capability(capability)?;
        self.send_request(
            descriptor,
            "/v1/mailbox/post",
            &MailboxPostApiRequest {
                namespace: descriptor.namespace.clone(),
                capability_id: capability.capability_id.clone(),
                access_key_b64: capability.access_key_b64.clone(),
                auth_token_b64: capability.auth_token_b64.clone(),
                bootstrap_token: capability.bootstrap_token.clone(),
                message: message.clone(),
            },
        )
        .await
    }

    async fn poll_messages(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        request: &MailboxPollRequest,
    ) -> Result<MailboxPollResult> {
        Self::validate_descriptor(descriptor)?;
        Self::validate_capability(capability)?;
        self.send_request(
            descriptor,
            "/v1/mailbox/poll",
            &MailboxPollApiRequest {
                namespace: descriptor.namespace.clone(),
                capability_id: capability.capability_id.clone(),
                access_key_b64: capability.access_key_b64.clone(),
                auth_token_b64: capability.auth_token_b64.clone(),
                bootstrap_token: capability.bootstrap_token.clone(),
                cursor: request.cursor.clone(),
                limit: request.limit,
            },
        )
        .await
    }

    async fn ack_messages(
        &self,
        descriptor: &MailboxDescriptor,
        capability: &MailboxCapability,
        envelope_ids: &[String],
    ) -> Result<()> {
        Self::validate_descriptor(descriptor)?;
        Self::validate_capability(capability)?;
        self.send_empty_ok(
            descriptor,
            "/v1/mailbox/ack",
            &MailboxAckApiRequest {
                namespace: descriptor.namespace.clone(),
                capability_id: capability.capability_id.clone(),
                access_key_b64: capability.access_key_b64.clone(),
                auth_token_b64: capability.auth_token_b64.clone(),
                bootstrap_token: capability.bootstrap_token.clone(),
                envelope_ids: envelope_ids.to_vec(),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tempfile::tempdir;

    use crate::network::mailbox_bootstrap::issue_mailbox_bootstrap_token;
    use crate::network::mailbox_service::spawn_loopback_mailbox_service;
    use crate::network::mailbox_transport::MailboxPollRequest;
    use crate::network::protocol::{
        GroupMailboxMessage, GroupMailboxMessageKind, MailboxBootstrapScopeKind,
    };

    fn test_descriptor(endpoint: String, namespace: &str) -> MailboxDescriptor {
        MailboxDescriptor {
            transport: MailboxTransportKind::Tor,
            namespace: namespace.to_string(),
            endpoint: Some(endpoint),
            poll_interval_ms: 5_000,
            max_payload_bytes: 256 * 1024,
        }
    }

    fn test_capability(namespace: &str) -> MailboxCapability {
        let mut capability = MailboxCapability {
            capability_id: "cap_test".to_string(),
            access_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
            auth_token_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]),
            bootstrap_token: None,
        };
        capability.bootstrap_token = Some(
            issue_mailbox_bootstrap_token(
                &ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
                MailboxBootstrapScopeKind::Invite,
                namespace,
                namespace,
                &capability,
                chrono::Utc::now().timestamp().max(0) as u64 + 3_600,
            )
            .unwrap(),
        );
        capability
    }

    fn test_message(group_id: &str, message_id: &str) -> GroupMailboxMessage {
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
            ciphertext: vec![9, 8, 7],
        }
    }

    fn future_message(group_id: &str, message_id: &str) -> GroupMailboxMessage {
        let mut message = test_message(group_id, message_id);
        message.created_at = (chrono::Utc::now().timestamp() + 3600) as u64;
        message
    }

    #[tokio::test]
    async fn loopback_mailbox_service_roundtrip_works() {
        let temp = tempdir().unwrap();
        let (addr, handle) = spawn_loopback_mailbox_service(temp.path().to_path_buf(), 256 * 1024)
            .await
            .unwrap();
        let transport = TorMailboxTransport::new(temp.path().join("client-tor"));
        let descriptor =
            test_descriptor(format!("http://127.0.0.1:{}", addr.port()), "mailbox:grp1");
        let capability = test_capability(&descriptor.namespace);

        let receipt = transport
            .post_message(&descriptor, &capability, &test_message("grp1", "m1"))
            .await
            .unwrap();
        assert_eq!(receipt.message_id, "m1");

        let result = transport
            .poll_messages(
                &descriptor,
                &capability,
                &MailboxPollRequest {
                    cursor: None,
                    limit: 10,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].message.group_id, "grp1");

        transport
            .ack_messages(
                &descriptor,
                &capability,
                &[result.items[0].envelope_id.clone()],
            )
            .await
            .unwrap();
        handle.abort();
    }

    #[tokio::test]
    async fn loopback_mailbox_isolated_by_namespace() {
        let temp = tempdir().unwrap();
        let (addr, handle) = spawn_loopback_mailbox_service(temp.path().to_path_buf(), 256 * 1024)
            .await
            .unwrap();
        let transport = TorMailboxTransport::new(temp.path().join("client-tor"));
        let group_a = test_descriptor(format!("http://127.0.0.1:{}", addr.port()), "mailbox:grpA");
        let group_b = test_descriptor(format!("http://127.0.0.1:{}", addr.port()), "mailbox:grpB");
        let capability_a = test_capability(&group_a.namespace);
        let capability_b = test_capability(&group_b.namespace);

        transport
            .post_message(&group_a, &capability_a, &test_message("grpA", "ma"))
            .await
            .unwrap();

        let result = transport
            .poll_messages(
                &group_b,
                &capability_b,
                &MailboxPollRequest {
                    cursor: None,
                    limit: 10,
                },
            )
            .await
            .unwrap();
        assert!(result.items.is_empty());
        handle.abort();
    }

    #[tokio::test]
    async fn loopback_mailbox_rejects_future_timestamp() {
        let temp = tempdir().unwrap();
        let (addr, handle) = spawn_loopback_mailbox_service(temp.path().to_path_buf(), 256 * 1024)
            .await
            .unwrap();
        let transport = TorMailboxTransport::new(temp.path().join("client-tor"));
        let descriptor = test_descriptor(
            format!("http://127.0.0.1:{}", addr.port()),
            "mailbox:grpFuture",
        );
        let capability = test_capability(&descriptor.namespace);

        let error = transport
            .post_message(
                &descriptor,
                &capability,
                &future_message("grpFuture", "future-1"),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("future"));
        handle.abort();
    }

    #[tokio::test]
    async fn loopback_mailbox_rate_limits_post_burst() {
        let temp = tempdir().unwrap();
        let (addr, handle) = spawn_loopback_mailbox_service(temp.path().to_path_buf(), 256 * 1024)
            .await
            .unwrap();
        let transport = TorMailboxTransport::new(temp.path().join("client-tor"));
        let descriptor = test_descriptor(
            format!("http://127.0.0.1:{}", addr.port()),
            "mailbox:grpRate",
        );
        let capability = test_capability(&descriptor.namespace);

        let mut rejection = None;
        for index in 0..240usize {
            match transport
                .post_message(
                    &descriptor,
                    &capability,
                    &test_message("grpRate", &format!("m{}", index)),
                )
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    rejection = Some(error);
                    break;
                }
            }
        }

        let error = match rejection {
            Some(error) => error,
            None => transport
                .post_message(
                    &descriptor,
                    &capability,
                    &test_message("grpRate", "overflow"),
                )
                .await
                .unwrap_err(),
        };
        assert!(
            error.to_string().contains("rate limit") || error.to_string().contains("backlog full")
        );
        handle.abort();
    }
}
