use super::*;

pub(crate) fn redacted_log_marker(label: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"Qypha-GroupMailbox-LogRedaction-v1");
    hasher.update(label.as_bytes());
    hasher.update(value.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{}#{}", label, &digest[..12])
}

pub(crate) fn maybe_redact_log_value(log_mode: &LogMode, label: &str, value: &str) -> String {
    if matches!(log_mode, LogMode::Safe) {
        redacted_log_marker(label, value)
    } else {
        value.to_string()
    }
}

pub(crate) fn fast_file_grant_state_key(transfer_id: &str, recipient_member_id: &str) -> String {
    format!("{transfer_id}:{recipient_member_id}")
}

pub(crate) fn log_group_id(log_mode: &LogMode, group_id: &str) -> String {
    maybe_redact_log_value(log_mode, "group", group_id)
}

pub(crate) fn log_message_id(log_mode: &LogMode, message_id: &str) -> String {
    maybe_redact_log_value(log_mode, "message", message_id)
}

pub(crate) fn log_member_id(log_mode: &LogMode, member_id: &str) -> String {
    maybe_redact_log_value(log_mode, "member", member_id)
}

pub(crate) fn log_transfer_id(log_mode: &LogMode, transfer_id: &str) -> String {
    maybe_redact_log_value(log_mode, "transfer", transfer_id)
}

pub(crate) fn log_manifest_id(log_mode: &LogMode, manifest_id: &str) -> String {
    maybe_redact_log_value(log_mode, "manifest", manifest_id)
}

pub(crate) fn log_mailbox_namespace(log_mode: &LogMode, namespace: &str) -> String {
    maybe_redact_log_value(log_mode, "mailbox_namespace", namespace)
}

pub(crate) fn log_mailbox_endpoint(log_mode: &LogMode, endpoint: &str) -> String {
    maybe_redact_log_value(log_mode, "mailbox_endpoint", endpoint)
}

pub(crate) fn log_mailbox_cursor(log_mode: &LogMode, cursor: &str) -> String {
    maybe_redact_log_value(log_mode, "mailbox_cursor", cursor)
}

pub(crate) fn format_error_chain(error: &anyhow::Error) -> String {
    let mut formatted = String::new();
    for (index, cause) in error.chain().enumerate() {
        let cause = cause.to_string();
        if cause.trim().is_empty() {
            continue;
        }
        if index > 0 && !formatted.is_empty() {
            formatted.push_str(" <- ");
        }
        formatted.push_str(&cause);
    }
    formatted
}

pub(crate) fn mailbox_transport_error_is_unreachable(error: &anyhow::Error) -> bool {
    let rendered = format_error_chain(error).to_ascii_lowercase();
    rendered.contains("failed to connect to tor mailbox")
        || rendered.contains("failed to connect to loopback mailbox")
        || rendered.contains("tor operation timed out")
        || rendered.contains("unable to connect to hidden service")
        || rendered.contains("introduction point")
}

pub(crate) fn print_mailbox_background_retry_notice(group_label: &str) {
    println!(
        "   {} {}",
        "Mailbox:".yellow().bold(),
        format!("{group_label} host is offline; retrying in background").dimmed()
    );
}

pub(crate) fn print_mailbox_recovered_notice(group_label: &str) {
    println!(
        "   {} {}",
        "Mailbox:".yellow().bold(),
        format!("{group_label} host is reachable again").dimmed()
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MailboxPollLogContext {
    pub(crate) endpoint: String,
    pub(crate) endpoint_kind: &'static str,
    pub(crate) endpoint_host: String,
    pub(crate) endpoint_port: u16,
    pub(crate) endpoint_port_known: bool,
    pub(crate) namespace: String,
    pub(crate) local_embedded_service_group_id: Option<String>,
    pub(crate) local_embedded_service_status: &'static str,
}

pub(crate) async fn mailbox_poll_log_context(
    log_mode: &LogMode,
    descriptor: &MailboxDescriptor,
    agent_data_dir: &Path,
) -> MailboxPollLogContext {
    let endpoint = descriptor
        .endpoint
        .as_deref()
        .map(|value| log_mailbox_endpoint(log_mode, value))
        .unwrap_or_else(|| "missing".to_string());
    let namespace = log_mailbox_namespace(log_mode, &descriptor.namespace);
    let (endpoint_kind, endpoint_host, endpoint_port, endpoint_port_known) =
        match descriptor.endpoint.as_deref() {
            Some(raw_endpoint) => match parse_mailbox_service_endpoint(raw_endpoint) {
                Ok(MailboxServiceEndpoint::Tor { onion, port }) => (
                    "tor",
                    maybe_redact_log_value(log_mode, "mailbox_host", &onion),
                    port,
                    true,
                ),
                Ok(MailboxServiceEndpoint::LoopbackHttp { host, port }) => (
                    "loopback_http",
                    maybe_redact_log_value(log_mode, "mailbox_host", &host),
                    port,
                    true,
                ),
                Err(_) => ("invalid", endpoint.clone(), 0, false),
            },
            None => ("missing", "missing".to_string(), 0, false),
        };
    let (local_embedded_service_group_id, local_embedded_service_status) = match descriptor
        .endpoint
        .as_deref()
    {
        Some(raw_endpoint) => {
            match local_embedded_mailbox_service_group_id_for_endpoint(agent_data_dir, raw_endpoint)
            {
                Some(group_id) => {
                    let service_root = auto_mailbox_service_root(agent_data_dir, &group_id);
                    let services = embedded_mailbox_services().lock().await;
                    let status = match services.get(&service_root) {
                        Some(state) if state.handle.is_finished() => "stopped",
                        Some(_) => "running",
                        None => "not_registered",
                    };
                    (Some(log_group_id(log_mode, &group_id)), status)
                }
                None => (None, "remote"),
            }
        }
        None => (None, "missing"),
    };
    MailboxPollLogContext {
        endpoint,
        endpoint_kind,
        endpoint_host,
        endpoint_port,
        endpoint_port_known,
        namespace,
        local_embedded_service_group_id,
        local_embedded_service_status,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupMailboxPartialAckReason {
    RotationAppliedMidBatch,
    ProcessingDeferred,
}

impl GroupMailboxPartialAckReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RotationAppliedMidBatch => "rotation_applied_mid_batch",
            Self::ProcessingDeferred => "processing_deferred",
        }
    }
}
