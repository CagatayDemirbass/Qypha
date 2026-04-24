use std::sync::Arc;

use colored::Colorize;

use super::incoming_connect_gate::IncomingConnectGate;
use super::*;
use crate::network::contact_mailbox::{ContactMailboxAckRequest, ContactMailboxPollRequest};
use crate::network::contact_mailbox_transport::ContactMailboxTransport;
use crate::network::did_profile::DidContactService;

fn local_tor_contact_service(
    config: &AppConfig,
    keypair: &AgentKeyPair,
) -> Option<DidContactService> {
    crate::network::discovery::build_local_did_profile(keypair, config, None)
        .ok()
        .and_then(|profile| {
            profile
                .services
                .into_iter()
                .find(|service| matches!(service, DidContactService::TorMailbox { .. }))
        })
}

async fn record_mailbox_contact_request(
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    our_did: &str,
    sender_did: &str,
) {
    let mut locked = audit.lock().await;
    locked.record(
        "CONTACT_REQUEST_PENDING",
        our_did,
        &format!("from_did={} delivery=tor_mailbox", sender_did),
    );
}

async fn record_mailbox_contact_request_blocked(
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    our_did: &str,
    sender_did: &str,
) {
    let mut locked = audit.lock().await;
    locked.record(
        "CONTACT_REQUEST_BLOCKED",
        our_did,
        &format!("from_did={} delivery=tor_mailbox", sender_did),
    );
}

async fn record_mailbox_contact_accept(
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    our_did: &str,
    responder_did: &str,
    request_id: &str,
) {
    let mut locked = audit.lock().await;
    locked.record(
        "CONTACT_REQUEST_ACCEPTED",
        our_did,
        &format!(
            "request_id={} responder_did={} delivery=tor_mailbox",
            request_id, responder_did
        ),
    );
}

async fn record_mailbox_contact_reject(
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    our_did: &str,
    responder_did: &str,
    request_id: &str,
) {
    let mut locked = audit.lock().await;
    locked.record(
        "CONTACT_REQUEST_REJECTED",
        our_did,
        &format!(
            "request_id={} responder_did={} delivery=tor_mailbox",
            request_id, responder_did
        ),
    );
}

fn display_contact_did(profile: &crate::network::did_profile::DidProfile) -> String {
    crate::network::contact_did::encode_contact_did(profile).unwrap_or_else(|_| profile.did.clone())
}

pub(crate) async fn poll_contact_mailbox_once(
    transport: &ContactMailboxTransport,
    config: &AppConfig,
    keypair: &AgentKeyPair,
    pending_contact_requests: &Arc<tokio::sync::Mutex<ContactRequestRegistry>>,
    incoming_connect_gate: &Arc<tokio::sync::Mutex<IncomingConnectGate>>,
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    peer_store: &Arc<tokio::sync::Mutex<PeerStore>>,
    direct_peer_dids: &Arc<DashMap<String, bool>>,
    log_mode: &LogMode,
    agent_name: &str,
) {
    let Some(service) = local_tor_contact_service(config, keypair) else {
        return;
    };
    let DidContactService::TorMailbox {
        mailbox_namespace, ..
    } = &service
    else {
        return;
    };

    let poll_request = ContactMailboxPollRequest::sign(
        keypair.did.clone(),
        mailbox_namespace.clone(),
        None,
        &keypair.signing_key,
    );
    let poll_result = match transport.poll(&service, &poll_request).await {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(%error, "Contact mailbox poll failed");
            return;
        }
    };

    if poll_result.items.is_empty() {
        return;
    }

    let mut ack_ids = Vec::new();
    for item in poll_result.items {
        ack_ids.push(item.envelope_id.clone());
        match item.request.msg_type {
            MessageKind::ContactRequest => {
                match crate::network::contact_request::open_contact_request_agent_request(
                    keypair,
                    &item.request,
                ) {
                    Ok(payload) => {
                        let sender_did = payload.sender_profile.did.clone();
                        let blocked = {
                            let gate = incoming_connect_gate.lock().await;
                            gate.is_block_all() || gate.is_did_blocked(&sender_did)
                        };
                        if blocked {
                            tracing::info!(
                                sender_did = %sender_did,
                                "Blocked contact request dropped from Tor mailbox"
                            );
                            record_mailbox_contact_request_blocked(
                                audit,
                                &config.agent.did,
                                &sender_did,
                            )
                            .await;
                            continue;
                        }
                        let display_did = display_contact_did(&payload.sender_profile);
                        let is_new = {
                            let mut registry = pending_contact_requests.lock().await;
                            registry
                                .upsert_mailbox(item.request.sender_name.clone(), payload.clone())
                        };
                        println!(
                            "\n   {} {} ({}) {}",
                            "Contact request:".green().bold(),
                            item.request.sender_name.cyan(),
                            display_did.dimmed(),
                            "via Tor mailbox".dimmed()
                        );
                        if let Some(intro) = payload.intro_message.as_deref() {
                            println!("   {} {}", "Intro:".yellow().bold(), intro);
                        }
                        println!(
                            "   {} /accept {}   {} /reject {}",
                            "Review:".dimmed(),
                            display_did.white().bold(),
                            "or".dimmed(),
                            display_did.white().bold()
                        );
                        if is_new {
                            record_mailbox_contact_request(audit, &config.agent.did, &sender_did)
                                .await;
                        }
                        print_prompt(agent_name);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Mailbox contact request failed to open");
                    }
                }
            }
            MessageKind::ContactAccept => {
                match crate::network::contact_request::open_contact_accept_agent_request(
                    keypair,
                    &item.request,
                ) {
                    Ok(payload) => {
                        let promotion = promote_accepted_contact(
                            &payload.responder_profile,
                            &item.request.sender_name,
                            &item.request.sender_role,
                            log_mode,
                            peer_store,
                            direct_peer_dids,
                            None,
                            None,
                            None,
                        )
                        .await;
                        let responder_display_did = display_contact_did(&payload.responder_profile);
                        println!(
                            "\n   {} {} ({}) {}",
                            "Contact accepted:".green().bold(),
                            item.request.sender_name.cyan(),
                            responder_display_did.dimmed(),
                            "via Tor mailbox".dimmed()
                        );
                        print_trusted_contact_promotion(promotion);
                        record_mailbox_contact_accept(
                            audit,
                            &config.agent.did,
                            &payload.responder_profile.did,
                            &payload.request_id,
                        )
                        .await;
                        print_prompt(agent_name);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Mailbox contact accept failed to open");
                    }
                }
            }
            MessageKind::ContactReject => {
                match crate::network::contact_request::open_contact_reject_agent_request(
                    keypair,
                    &item.request,
                ) {
                    Ok(payload) => {
                        let responder_display_did = display_contact_did(&payload.responder_profile);
                        println!(
                            "\n   {} {} ({}) {}",
                            "Contact rejected:".yellow().bold(),
                            item.request.sender_name.cyan(),
                            responder_display_did.dimmed(),
                            "via Tor mailbox".dimmed()
                        );
                        if let Some(reason) = payload.reason.as_deref() {
                            println!("   {} {}", "Reason:".yellow().bold(), reason);
                        }
                        record_mailbox_contact_reject(
                            audit,
                            &config.agent.did,
                            &payload.responder_profile.did,
                            &payload.request_id,
                        )
                        .await;
                        print_prompt(agent_name);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Mailbox contact reject failed to open");
                    }
                }
            }
            _ => {}
        }
    }

    if ack_ids.is_empty() {
        return;
    }

    let ack_request = ContactMailboxAckRequest::sign(
        keypair.did.clone(),
        mailbox_namespace.clone(),
        ack_ids,
        &keypair.signing_key,
    );
    if let Err(error) = transport.ack(&service, &ack_request).await {
        tracing::warn!(%error, "Contact mailbox ack failed");
    }
}
