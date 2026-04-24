use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arti_client::{TorClient, TorClientConfig};
use tokio::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;

use super::group_invite_bundle::{
    GroupInviteBundleGetRequest, GroupInviteBundleGetResponse, GroupInviteBundlePutRequest,
};
use super::mailbox_transport::MailboxServiceEndpoint;

#[derive(Clone)]
pub struct GroupInviteBundleTransport {
    tor_data_dir: Arc<PathBuf>,
    tor_client: Arc<OnceCell<Arc<TorClient<PreferredRuntime>>>>,
}

impl GroupInviteBundleTransport {
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
                    .context("Failed to build group invite bundle Tor client config")?;
                let client = TorClient::create_bootstrapped(config)
                    .await
                    .context("Failed to bootstrap group invite bundle Tor client")?;
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
        match super::mailbox_transport::parse_mailbox_service_endpoint(endpoint)? {
            MailboxServiceEndpoint::Tor { onion, port } => {
                let client = self.tor_client().await?;
                let stream = client
                    .connect((format!("{}.onion", onion), port))
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to connect to group invite bundle service {onion}.onion:{port}"
                        )
                    })?;
                super::contact_bundle_transport::send_json_over_stream(
                    stream,
                    &format!("{}.onion", onion),
                    path,
                    request,
                )
                .await
            }
            MailboxServiceEndpoint::LoopbackHttp { host, port } => {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to connect to loopback group invite bundle service {host}:{port}"
                        )
                    })?;
                super::contact_bundle_transport::send_json_over_stream(stream, &host, path, request)
                    .await
            }
        }
    }

    pub async fn put_to_endpoint(
        &self,
        endpoint: &str,
        request: &GroupInviteBundlePutRequest,
    ) -> Result<()> {
        let _: serde_json::Value = self
            .send_request(endpoint, "/v1/group-invite-bundle/put", request)
            .await?;
        Ok(())
    }

    pub async fn get_from_endpoint(
        &self,
        endpoint: &str,
        request: &GroupInviteBundleGetRequest,
    ) -> Result<GroupInviteBundleGetResponse> {
        self.send_request(endpoint, "/v1/group-invite-bundle/get", request)
            .await
    }
}
