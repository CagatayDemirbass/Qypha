use libp2p::PeerId;

pub mod codec;
pub mod contact_bundle;
pub mod contact_bundle_iroh;
pub mod contact_bundle_store;
pub mod contact_bundle_transport;
pub mod contact_did;
pub mod contact_mailbox;
pub mod contact_mailbox_store;
pub mod contact_mailbox_transport;
pub mod contact_request;
pub mod did_profile;
pub mod did_profile_store;
pub mod direct_invite_token;
pub mod discovery;
pub mod group_invite_bundle;
pub mod group_invite_bundle_iroh;
pub mod group_invite_bundle_store;
pub mod group_invite_bundle_transport;
pub mod invite;
pub mod iroh_transport;
pub mod mailbox_bootstrap;
pub mod mailbox_service;
pub mod mailbox_transport;
pub mod node;
pub mod peer_store;
pub mod protocol;
pub mod tor_bridge;
pub mod tor_mailbox;
pub mod tor_transport;

#[derive(Debug, Clone)]
pub struct IncomingRequestEnvelope {
    pub peer_id: PeerId,
    pub request: protocol::AgentRequest,
    pub iroh_stable_id: Option<usize>,
    pub iroh_active_session: Option<bool>,
}

pub use node::NetworkNode;
pub use protocol::{AgentRequest, AgentResponse, MessageKind};
