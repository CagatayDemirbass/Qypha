use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arti_client::{TorClient, TorClientConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;

use super::contact_bundle::{
    ContactBundleGetRequest, ContactBundleGetResponse, ContactBundlePutRequest,
};
use super::mailbox_transport::{parse_mailbox_service_endpoint, MailboxErrorResponse};

#[derive(Clone)]
pub struct ContactBundleTransport {
    tor_data_dir: Arc<PathBuf>,
    tor_client: Arc<OnceCell<Arc<TorClient<PreferredRuntime>>>>,
}

impl ContactBundleTransport {
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
                    .context("Failed to build contact bundle Tor client config")?;
                let client = TorClient::create_bootstrapped(config)
                    .await
                    .context("Failed to bootstrap contact bundle Tor client")?;
                Ok::<_, anyhow::Error>(Arc::new(client))
            })
            .await
            .cloned()
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
            super::mailbox_transport::MailboxServiceEndpoint::Tor { onion, port } => {
                let client = self.tor_client().await?;
                let stream = client
                    .connect((format!("{}.onion", onion), port))
                    .await
                    .with_context(|| {
                        format!("Failed to connect to contact bundle service {onion}.onion:{port}")
                    })?;
                send_json_over_stream(stream, &format!("{}.onion", onion), path, request).await
            }
            super::mailbox_transport::MailboxServiceEndpoint::LoopbackHttp { host, port } => {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to connect to loopback contact bundle service {host}:{port}"
                        )
                    })?;
                send_json_over_stream(stream, &host, path, request).await
            }
        }
    }

    pub async fn put_to_endpoint(
        &self,
        endpoint: &str,
        request: &ContactBundlePutRequest,
    ) -> Result<()> {
        let _: serde_json::Value = self
            .send_request(endpoint, "/v1/contact-bundle/put", request)
            .await?;
        Ok(())
    }

    pub async fn get_from_endpoint(
        &self,
        endpoint: &str,
        request: &ContactBundleGetRequest,
    ) -> Result<ContactBundleGetResponse> {
        self.send_request(endpoint, "/v1/contact-bundle/get", request)
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
            bail!("Contact bundle HTTP response ended before headers");
        }
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }

    let header_bytes = &buffer[..header_end];
    let header_text = std::str::from_utf8(header_bytes)
        .context("Contact bundle HTTP response headers are not valid UTF-8")?;
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Contact bundle HTTP response missing status line"))?;
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
        Vec::new()
    } else {
        buffer[header_end..std::cmp::min(buffer.len(), header_end + content_length)].to_vec()
    };
    Ok((status, body))
}

pub(crate) async fn send_json_over_stream<S, TReq, TRes>(
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
    let body = serde_json::to_vec(request).context("Failed to encode contact bundle request")?;
    let http = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        body.len()
    );
    stream.write_all(http.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let (status, body) = read_http_response(stream).await?;
    if (200..300).contains(&status) {
        if body.is_empty() {
            return serde_json::from_str("null").context("Empty contact bundle response body");
        }
        serde_json::from_slice(&body).context("Failed to decode contact bundle response")
    } else {
        let error = serde_json::from_slice::<MailboxErrorResponse>(&body)
            .map(|err| err.error)
            .unwrap_or_else(|_| format!("HTTP {}", status));
        bail!(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::contact_did::encode_contact_did;
    use crate::network::discovery::build_local_did_profile_with_iroh_contact_endpoint;
    use crate::network::mailbox_service::spawn_loopback_mailbox_service;
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
    async fn loopback_contact_bundle_roundtrip_works() {
        let temp = tempfile::tempdir().unwrap();
        let (addr, handle) = spawn_loopback_mailbox_service(temp.path().to_path_buf(), 256 * 1024)
            .await
            .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", addr.port());

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

        let transport = ContactBundleTransport::new(temp.path().join("tor-client"));
        transport
            .put_to_endpoint(
                &endpoint,
                &ContactBundlePutRequest::new(contact_did.clone(), profile.clone()),
            )
            .await
            .unwrap();

        let response = transport
            .get_from_endpoint(&endpoint, &ContactBundleGetRequest::new(contact_did))
            .await
            .unwrap();
        assert_eq!(response.into_verified_profile().unwrap(), Some(profile));

        handle.abort();
    }
}
