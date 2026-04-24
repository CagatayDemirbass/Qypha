use super::*;
use crate::crypto::signing;
use crate::network::protocol::FastTransferOpenPayload;

pub(crate) fn fast_transfer_open_signing_data(payload: &FastTransferOpenPayload) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(b"Qypha-FastTransferOpen-v1:");
    data.extend_from_slice(payload.transfer_id.as_bytes());
    data.push(0);
    data.extend_from_slice(payload.group_id.as_bytes());
    data.push(0);
    data.extend_from_slice(payload.recipient_did.as_bytes());
    data.push(0);
    data.extend_from_slice(payload.recipient_verifying_key_hex.as_bytes());
    data.push(0);
    data.extend_from_slice(payload.ticket_id.as_bytes());
    data.push(0);
    data.extend_from_slice(payload.created_at.to_string().as_bytes());
    data
}

pub(crate) fn build_fast_transfer_open_request(
    keypair: &AgentKeyPair,
    ttl_ms: u64,
    transfer_id: String,
    group_id: String,
    recipient_did: String,
    recipient_verifying_key_hex: String,
    ticket_id: String,
) -> Result<AgentRequest> {
    let mut payload = FastTransferOpenPayload {
        transfer_id,
        group_id,
        recipient_did,
        recipient_verifying_key_hex,
        ticket_id,
        created_at: chrono::Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    payload.signature = signing::sign_data(
        &keypair.signing_key,
        &fast_transfer_open_signing_data(&payload),
    );
    let bytes = bincode::serialize(&payload)?;
    chunked_transfer::wrap_chunk_request(keypair, MessageKind::FastTransferOpen, bytes, ttl_ms)
}

pub(crate) fn build_transfer_accept_request(
    keypair: &AgentKeyPair,
    ttl_ms: u64,
    session_id: String,
    received_chunks: Vec<usize>,
) -> Result<AgentRequest> {
    let payload = crate::network::protocol::TransferResumePayload {
        session_id,
        received_chunks,
    };
    let bytes = bincode::serialize(&payload)?;
    chunked_transfer::wrap_chunk_request(keypair, MessageKind::TransferResume, bytes, ttl_ms)
}

pub(crate) fn build_transfer_reject_request(
    keypair: &AgentKeyPair,
    ttl_ms: u64,
    session_id: Option<String>,
    request_message_id: Option<String>,
    reason: String,
) -> Result<AgentRequest> {
    let payload = crate::network::protocol::TransferRejectPayload {
        session_id,
        request_message_id,
        reason,
    };
    let bytes = bincode::serialize(&payload)?;
    chunked_transfer::wrap_chunk_request(keypair, MessageKind::TransferReject, bytes, ttl_ms)
}

pub(crate) fn build_transfer_status_request(
    keypair: &AgentKeyPair,
    ttl_ms: u64,
    session_id: Option<String>,
    request_message_id: Option<String>,
    filename: Option<String>,
    status: String,
    detail: Option<String>,
) -> Result<AgentRequest> {
    let payload = crate::network::protocol::TransferStatusPayload {
        session_id,
        request_message_id,
        filename,
        status,
        detail,
    };
    let bytes = bincode::serialize(&payload)?;
    chunked_transfer::wrap_chunk_request(keypair, MessageKind::TransferStatus, bytes, ttl_ms)
}

pub(crate) fn transfer_session_matches(
    requested_session_id: Option<&str>,
    actual_session_id: &str,
) -> bool {
    requested_session_id.map_or(true, |session_id| session_id == actual_session_id)
}
