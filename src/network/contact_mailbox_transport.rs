use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arti_client::{TorClient, TorClientConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;

use crate::network::contact_mailbox::{
    ContactMailboxAckRequest, ContactMailboxPollRequest, ContactMailboxPollResult,
    ContactMailboxPostRequest,
};
use crate::network::did_profile::DidContactService;
use crate::network::mailbox_transport::{parse_mailbox_service_endpoint, MailboxErrorResponse};

#[derive(Clone)]
pub struct ContactMailboxTransport {
    tor_data_dir: Arc<PathBuf>,
    tor_client: Arc<OnceCell<Arc<TorClient<PreferredRuntime>>>>,
}

impl ContactMailboxTransport {
    pub fn new(tor_data_dir: PathBuf) -> Self {
        Self {
            tor_data_dir: Arc::new(tor_data_dir),
            tor_client: Arc::new(OnceCell::new()),
        }
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
                    .context("Failed to build contact mailbox Tor client config")?;
                let client = TorClient::create_bootstrapped(config)
                    .await
                    .context("Failed to bootstrap contact mailbox Tor client")?;
                Ok::<_, anyhow::Error>(Arc::new(client))
            })
            .await
            .cloned()
    }

    fn service_endpoint(service: &DidContactService) -> Result<String> {
        match service {
            DidContactService::TorMailbox {
                onion_address,
                port,
                ..
            } => Ok(format!("tor://{}.onion:{}", onion_address, port)),
            DidContactService::TorDirect { .. } => {
                bail!("Tor direct contact services must use the peer transport, not mailbox HTTP")
            }
            DidContactService::IrohRelay { .. } => {
                bail!("Iroh relay contact delivery is not wired yet")
            }
        }
    }

    async fn send_request<TReq, TRes>(
        &self,
        endpoint: &str,
        path: &str,
        request: &TReq,
    ) -> Result<TRes>
    where
        TReq: serde::Serialize,
        TRes: serde::de::DeserializeOwned,
    {
        match parse_mailbox_service_endpoint(endpoint)? {
            crate::network::mailbox_transport::MailboxServiceEndpoint::Tor { onion, port } => {
                let client = self.tor_client().await?;
                let stream = client
                    .connect((format!("{}.onion", onion), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to contact mailbox {onion}.onion:{port}")
                    })?;
                send_json_over_stream(stream, &format!("{}.onion", onion), path, request).await
            }
            crate::network::mailbox_transport::MailboxServiceEndpoint::LoopbackHttp {
                host,
                port,
            } => {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to loopback contact mailbox {host}:{port}")
                    })?;
                send_json_over_stream(stream, &host, path, request).await
            }
        }
    }

    async fn send_empty_ok<TReq>(&self, endpoint: &str, path: &str, request: &TReq) -> Result<()>
    where
        TReq: serde::Serialize,
    {
        match parse_mailbox_service_endpoint(endpoint)? {
            crate::network::mailbox_transport::MailboxServiceEndpoint::Tor { onion, port } => {
                let client = self.tor_client().await?;
                let stream = client
                    .connect((format!("{}.onion", onion), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to contact mailbox {onion}.onion:{port}")
                    })?;
                send_empty_over_stream(stream, &format!("{}.onion", onion), path, request).await
            }
            crate::network::mailbox_transport::MailboxServiceEndpoint::LoopbackHttp {
                host,
                port,
            } => {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to loopback contact mailbox {host}:{port}")
                    })?;
                send_empty_over_stream(stream, &host, path, request).await
            }
        }
    }

    pub async fn post(
        &self,
        service: &DidContactService,
        request: &ContactMailboxPostRequest,
    ) -> Result<()> {
        let endpoint = Self::service_endpoint(service)?;
        self.post_to_endpoint(&endpoint, request).await
    }

    pub async fn post_to_endpoint(
        &self,
        endpoint: &str,
        request: &ContactMailboxPostRequest,
    ) -> Result<()> {
        let _: serde_json::Value = self
            .send_request(endpoint, "/v1/contact/post", request)
            .await?;
        Ok(())
    }

    pub async fn poll(
        &self,
        service: &DidContactService,
        request: &ContactMailboxPollRequest,
    ) -> Result<ContactMailboxPollResult> {
        let endpoint = Self::service_endpoint(service)?;
        self.poll_to_endpoint(&endpoint, request).await
    }

    pub async fn poll_to_endpoint(
        &self,
        endpoint: &str,
        request: &ContactMailboxPollRequest,
    ) -> Result<ContactMailboxPollResult> {
        self.send_request(endpoint, "/v1/contact/poll", request)
            .await
    }

    pub async fn ack(
        &self,
        service: &DidContactService,
        request: &ContactMailboxAckRequest,
    ) -> Result<()> {
        let endpoint = Self::service_endpoint(service)?;
        self.ack_to_endpoint(&endpoint, request).await
    }

    pub async fn ack_to_endpoint(
        &self,
        endpoint: &str,
        request: &ContactMailboxAckRequest,
    ) -> Result<()> {
        self.send_empty_ok(endpoint, "/v1/contact/ack", request)
            .await
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
            bail!("Contact mailbox HTTP response ended before headers");
        }
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }

    let header_bytes = &buffer[..header_end];
    let header_text = std::str::from_utf8(header_bytes)
        .context("Contact mailbox HTTP response headers are not valid UTF-8")?;
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Contact mailbox HTTP response missing status line"))?;
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
    let body = serde_json::to_vec(request).context("Failed to encode contact mailbox request")?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let (status, body) = read_http_response(stream).await?;
    if (200..300).contains(&status) {
        if body.is_empty() {
            return serde_json::from_str("null").context("Empty contact mailbox response body");
        }
        serde_json::from_slice(&body).context("Failed to decode contact mailbox response")
    } else if body.is_empty() {
        bail!("Contact mailbox request failed with HTTP {}", status);
    } else if let Ok(error) = serde_json::from_slice::<MailboxErrorResponse>(&body) {
        bail!(
            "Contact mailbox request failed with HTTP {}: {}",
            status,
            error.error
        );
    } else {
        bail!(
            "Contact mailbox request failed with HTTP {} and a malformed error body",
            status
        );
    }
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
    let body = serde_json::to_vec(request).context("Failed to encode contact mailbox request")?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let (status, body) = read_http_response(stream).await?;
    if (200..300).contains(&status) {
        return Ok(());
    }
    if body.is_empty() {
        bail!("Contact mailbox request failed with HTTP {}", status);
    }
    if let Ok(error) = serde_json::from_slice::<MailboxErrorResponse>(&body) {
        bail!(
            "Contact mailbox request failed with HTTP {}: {}",
            status,
            error.error
        );
    }
    bail!(
        "Contact mailbox request failed with HTTP {} and a malformed error body",
        status
    )
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
    use crate::network::mailbox_service::spawn_loopback_mailbox_service;
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
    async fn loopback_contact_mailbox_roundtrip_works() {
        let temp = tempfile::tempdir().unwrap();
        let (addr, handle) = spawn_loopback_mailbox_service(temp.path().to_path_buf(), 256 * 1024)
            .await
            .unwrap();

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

        let transport = ContactMailboxTransport::new(temp.path().join("tor-client"));
        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        transport.post_to_endpoint(&endpoint, &post).await.unwrap();

        let poll = ContactMailboxPollRequest::sign(
            recipient.did.clone(),
            "contact:test".to_string(),
            None,
            &recipient.signing_key,
        );
        let polled = transport.poll_to_endpoint(&endpoint, &poll).await.unwrap();
        assert_eq!(polled.items.len(), 1);
        let envelope_id = polled.items[0].envelope_id.clone();

        let ack = ContactMailboxAckRequest::sign(
            recipient.did.clone(),
            "contact:test".to_string(),
            vec![envelope_id],
            &recipient.signing_key,
        );
        transport.ack_to_endpoint(&endpoint, &ack).await.unwrap();

        let repoll = ContactMailboxPollRequest::sign(
            recipient.did.clone(),
            "contact:test".to_string(),
            None,
            &recipient.signing_key,
        );
        assert!(transport
            .poll_to_endpoint(&endpoint, &repoll)
            .await
            .unwrap()
            .items
            .is_empty());

        handle.abort();
    }
}
