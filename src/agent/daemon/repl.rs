use colored::Colorize;
use dashmap::DashMap;
use rustyline::ExternalPrinter;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI8, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use super::peer::PeerInfo;
use super::selectors::is_direct_peer;

static ACTIVE_PROMPT_TARGET_LABEL: Mutex<Option<String>> = Mutex::new(None);
static EXTERNAL_PRINTER: Mutex<Option<Box<dyn rustyline::ExternalPrinter + Send>>> =
    Mutex::new(None);
static ACTIVE_PROGRESS_LINE: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_active_prompt_target_label(label: Option<String>) {
    let mut guard = ACTIVE_PROMPT_TARGET_LABEL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = label;
}

fn current_prompt_target_label() -> Option<String> {
    ACTIVE_PROMPT_TARGET_LABEL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn try_print_via_external_printer(msg: String) -> bool {
    let mut guard = EXTERNAL_PRINTER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .as_mut()
        .and_then(|printer| printer.print(msg).ok())
        .is_some()
}

fn try_print_line_via_external_printer(mut msg: String) -> bool {
    if !msg.ends_with('\n') {
        msg.push('\n');
    }
    try_print_via_external_printer(msg)
}

#[derive(Debug, Clone)]
pub(crate) struct ReplPeerTarget {
    pub(crate) did: String,
    pub(crate) name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TabCycleHandler {
    pub(crate) triggered: Arc<AtomicBool>,
    pub(crate) direction: Arc<AtomicI8>,
    pub(crate) step: i8,
}

impl rustyline::ConditionalEventHandler for TabCycleHandler {
    fn handle(
        &self,
        _evt: &rustyline::Event,
        _n: rustyline::RepeatCount,
        _positive: bool,
        ctx: &rustyline::EventContext,
    ) -> Option<rustyline::Cmd> {
        if !ctx.line().trim().is_empty() {
            return None;
        }
        self.direction.store(self.step, Ordering::SeqCst);
        self.triggered.store(true, Ordering::SeqCst);
        Some(rustyline::Cmd::Interrupt)
    }
}

pub(crate) fn sorted_repl_peer_targets(
    peers: &DashMap<String, PeerInfo>,
    direct_peer_dids: &DashMap<String, bool>,
) -> Vec<ReplPeerTarget> {
    let mut peer_list: Vec<PeerInfo> = peers
        .iter()
        .filter_map(|entry| {
            let peer = entry.value();
            is_active_chat_peer(peer, direct_peer_dids).then(|| peer.clone())
        })
        .collect();
    peer_list.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.did.cmp(&b.did)));
    peer_list
        .into_iter()
        .map(|peer| ReplPeerTarget {
            did: peer.did,
            name: peer.name,
        })
        .collect()
}

fn is_active_chat_peer(peer: &PeerInfo, direct_peer_dids: &DashMap<String, bool>) -> bool {
    is_direct_peer(peer, direct_peer_dids) && peer.verifying_key.is_some()
}

fn displayed_peer_label(name: &str) -> String {
    if name.starts_with("did:nxf:") {
        crate::agent::contact_identity::displayed_did(name)
    } else {
        name.to_string()
    }
}

pub(crate) fn selected_reconnecting_direct_peer(
    peers: &DashMap<String, PeerInfo>,
    active_target_did: &Arc<Mutex<Option<String>>>,
    direct_peer_dids: &DashMap<String, bool>,
) -> Option<ReplPeerTarget> {
    let selected_did = {
        active_target_did
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }?;

    peers.iter().find_map(|entry| {
        let peer = entry.value();
        if peer.did == selected_did
            && is_direct_peer(peer, direct_peer_dids)
            && peer.verifying_key.is_none()
        {
            Some(ReplPeerTarget {
                did: peer.did.clone(),
                name: peer.name.clone(),
            })
        } else {
            None
        }
    })
}

pub(crate) fn ensure_active_repl_target(
    active_target_did: &Arc<Mutex<Option<String>>>,
    peers: &[ReplPeerTarget],
) -> Option<ReplPeerTarget> {
    let mut guard = active_target_did
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if peers.is_empty() {
        *guard = None;
        return None;
    }

    if let Some(did) = guard.as_ref() {
        if let Some(peer) = peers.iter().find(|p| &p.did == did) {
            return Some(peer.clone());
        }
    }

    let first = peers[0].clone();
    *guard = Some(first.did.clone());
    Some(first)
}

pub(crate) fn cycle_active_repl_target(
    active_target_did: &Arc<Mutex<Option<String>>>,
    peers: &[ReplPeerTarget],
    direction: i8,
) -> Option<ReplPeerTarget> {
    let mut guard = active_target_did
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if peers.is_empty() {
        *guard = None;
        return None;
    }

    let step = if direction < 0 { -1isize } else { 1isize };
    let current_idx = guard
        .as_ref()
        .and_then(|did| peers.iter().position(|p| &p.did == did))
        .unwrap_or(0) as isize;
    let next_idx = (current_idx + step).rem_euclid(peers.len() as isize) as usize;
    let selected = peers[next_idx].clone();
    *guard = Some(selected.did.clone());
    Some(selected)
}

pub(crate) fn peer_prompt_label(selected: &ReplPeerTarget, peers: &[ReplPeerTarget]) -> String {
    let selected_name = displayed_peer_label(&selected.name);
    let same_name_count = peers
        .iter()
        .filter(|p| displayed_peer_label(&p.name) == selected_name)
        .count();
    if same_name_count <= 1 {
        return selected_name;
    }
    let short_did = crate::agent::contact_identity::displayed_did(&selected.did)
        .strip_prefix("did:qypha:")
        .unwrap_or(&selected.did)
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{}..{}", selected_name, short_did)
}

pub(crate) fn sync_active_direct_prompt_target(
    peers: &DashMap<String, PeerInfo>,
    active_target_did: &Arc<Mutex<Option<String>>>,
    direct_peer_dids: &DashMap<String, bool>,
    active_group_target_label: Option<&Arc<Mutex<Option<String>>>>,
) -> Option<ReplPeerTarget> {
    if active_group_target_label.is_some_and(|label| {
        label
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }) {
        return None;
    }

    let prompt_peers = sorted_repl_peer_targets(peers, direct_peer_dids);
    let reconnecting_selected =
        selected_reconnecting_direct_peer(peers, active_target_did, direct_peer_dids);
    let selected_peer = if prompt_peers.is_empty() {
        reconnecting_selected
    } else {
        ensure_active_repl_target(active_target_did, &prompt_peers).or(reconnecting_selected)
    };
    let label_peers = if let Some(selected) = selected_peer.as_ref() {
        if prompt_peers.iter().any(|peer| peer.did == selected.did) {
            prompt_peers.clone()
        } else {
            vec![selected.clone()]
        }
    } else {
        prompt_peers.clone()
    };
    let selected_label = selected_peer
        .as_ref()
        .map(|peer| peer_prompt_label(peer, &label_peers));
    set_active_prompt_target_label(selected_label);
    selected_peer
}

pub(crate) fn format_repl_prompt(
    agent_name: &str,
    selected_peer: Option<&ReplPeerTarget>,
    peers: &[ReplPeerTarget],
) -> String {
    if let Some(peer) = selected_peer {
        let label = peer_prompt_label(peer, peers);
        format!(
            "   \x1b[36m{}\x1b[0m[\x1b[33m{}\x1b[0m] > ",
            agent_name, label
        )
    } else {
        format!("   \x1b[36m{}\x1b[0m > ", agent_name)
    }
}

pub(crate) fn resolve_active_chat_peer(
    peers: &DashMap<String, PeerInfo>,
    active_target_did: &Arc<Mutex<Option<String>>>,
    direct_peer_dids: &DashMap<String, bool>,
) -> Option<PeerInfo> {
    let selected_did = {
        active_target_did
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }?;

    if let Some(peer) = peers.iter().find_map(|entry| {
        let p = entry.value();
        if p.did == selected_did && is_active_chat_peer(p, direct_peer_dids) {
            Some(p.clone())
        } else {
            None
        }
    }) {
        return Some(peer);
    }

    if selected_reconnecting_direct_peer(peers, active_target_did, direct_peer_dids).is_some() {
        return None;
    }

    let mut guard = active_target_did
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.as_deref() == Some(selected_did.as_str()) {
        *guard = None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyline::Result as RustylineResult;
    use std::sync::Arc;

    fn sample_peer(did: &str, name: &str, verified: bool) -> PeerInfo {
        PeerInfo {
            peer_id: libp2p::PeerId::random(),
            did: did.to_string(),
            name: name.to_string(),
            role: "agent".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            x25519_public_key: None,
            kyber_public_key: None,
            verifying_key: verified.then_some([7u8; 32]),
            aegis_supported: false,
            ratchet_dh_public: None,
        }
    }

    #[test]
    fn sorted_repl_targets_exclude_reconnecting_placeholders() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();

        let live = sample_peer("did:nxf:live", "agent2", true);
        let reconnecting = sample_peer("did:nxf:reconnecting", "agent3", false);

        direct_peer_dids.insert(live.did.clone(), true);
        direct_peer_dids.insert(reconnecting.did.clone(), true);
        peers.insert(live.peer_id.to_string(), live.clone());
        peers.insert(reconnecting.peer_id.to_string(), reconnecting);

        let targets = sorted_repl_peer_targets(&peers, &direct_peer_dids);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].did, live.did);
    }

    #[test]
    fn resolve_active_chat_peer_clears_disconnected_target() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();
        let active_target = Arc::new(Mutex::new(Some("did:nxf:missing".to_string())));

        assert!(resolve_active_chat_peer(&peers, &active_target, &direct_peer_dids).is_none());
        assert!(active_target.lock().unwrap().is_none());
    }

    #[test]
    fn resolve_active_chat_peer_preserves_reconnecting_target() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();
        let active_target = Arc::new(Mutex::new(Some("did:nxf:reconnecting".to_string())));

        let reconnecting = sample_peer("did:nxf:reconnecting", "agent2", false);
        direct_peer_dids.insert(reconnecting.did.clone(), true);
        peers.insert(reconnecting.peer_id.to_string(), reconnecting);

        assert!(resolve_active_chat_peer(&peers, &active_target, &direct_peer_dids).is_none());
        assert_eq!(
            *active_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            Some("did:nxf:reconnecting".to_string())
        );
    }

    #[test]
    fn duplicate_peer_names_use_did_suffix_in_prompt_label() {
        let peers = vec![
            ReplPeerTarget {
                did: "did:nxf:abcdef1234".to_string(),
                name: "agent2".to_string(),
            },
            ReplPeerTarget {
                did: "did:nxf:9876zzzz".to_string(),
                name: "agent2".to_string(),
            },
        ];

        assert_eq!(peer_prompt_label(&peers[0], &peers), "agent2..1234");
        assert_eq!(peer_prompt_label(&peers[1], &peers), "agent2..zzzz");
    }

    #[test]
    fn sync_active_direct_prompt_target_selects_only_verified_direct_peer() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();
        let active_target = Arc::new(Mutex::new(None));

        let peer = sample_peer("did:nxf:peer1234", "agent2", true);
        direct_peer_dids.insert(peer.did.clone(), true);
        peers.insert(peer.peer_id.to_string(), peer.clone());

        let selected =
            sync_active_direct_prompt_target(&peers, &active_target, &direct_peer_dids, None)
                .expect("expected active peer");

        assert_eq!(selected.did, peer.did);
        assert_eq!(
            *active_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            Some(peer.did)
        );
        set_active_prompt_target_label(None);
    }

    #[test]
    fn sync_active_direct_prompt_target_preserves_reconnecting_direct_peer() {
        let peers = DashMap::new();
        let direct_peer_dids = DashMap::new();
        let active_target = Arc::new(Mutex::new(Some("did:nxf:peer1234".to_string())));

        let peer = sample_peer("did:nxf:peer1234", "agent2", false);
        direct_peer_dids.insert(peer.did.clone(), true);
        peers.insert(peer.peer_id.to_string(), peer);

        let selected =
            sync_active_direct_prompt_target(&peers, &active_target, &direct_peer_dids, None)
                .expect("expected reconnecting peer target");

        assert_eq!(selected.did, "did:nxf:peer1234");
        assert_eq!(current_prompt_target_label().as_deref(), Some("agent2"));
        set_active_prompt_target_label(None);
    }

    #[test]
    fn fatal_readline_errors_request_shutdown() {
        assert!(should_request_shutdown_on_readline_error(
            &rustyline::error::ReadlineError::Eof
        ));
        assert!(should_request_shutdown_on_readline_error(
            &rustyline::error::ReadlineError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            ))
        ));
        assert!(!should_request_shutdown_on_readline_error(
            &rustyline::error::ReadlineError::Interrupted
        ));
        assert!(!should_request_shutdown_on_readline_error(
            &rustyline::error::ReadlineError::WindowResized
        ));
    }

    struct TestPrinter {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl rustyline::ExternalPrinter for TestPrinter {
        fn print(&mut self, msg: String) -> RustylineResult<()> {
            self.lines
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(msg);
            Ok(())
        }
    }

    #[test]
    fn progress_notice_uses_external_printer_when_available() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        set_external_printer(Some(Box::new(TestPrinter {
            lines: Arc::clone(&lines),
        })));
        ACTIVE_PROGRESS_LINE.store(false, Ordering::SeqCst);

        print_async_progress_notice("   Sending: [1/10] 10%".to_string());
        print_async_progress_notice("   Sending: [2/10] 20%".to_string());

        let captured = lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert_eq!(
            captured,
            vec![
                "   Sending: [1/10] 10%\n".to_string(),
                "\u{1b}[1A\r\u{1b}[2K   Sending: [2/10] 20%\n".to_string(),
            ]
        );
        assert!(ACTIVE_PROGRESS_LINE.load(Ordering::SeqCst));
        set_external_printer(None);
    }
}

pub(crate) fn print_prompt(agent_name: &str) {
    clear_async_progress_notice();
    // When rustyline is active, ask it to repaint the current prompt/input line
    // instead of writing a second raw prompt into stdout. This avoids duplicated
    // prompts and input-line corruption during heavy async notice traffic.
    if try_print_via_external_printer(String::new()) {
        return;
    }
    if let Some(label) = current_prompt_target_label() {
        print!("   {}[{}] > ", agent_name.cyan(), label.yellow());
    } else {
        print!("   {} > ", agent_name.cyan());
    }
    std::io::stdout().flush().unwrap();
}

pub(crate) fn clear_async_progress_notice() {
    if ACTIVE_PROGRESS_LINE.swap(false, Ordering::SeqCst) {
        if try_print_line_via_external_printer("\x1b[1A\r\x1b[2K".to_string()) {
            return;
        }
        print!("\r\x1b[2K");
        std::io::stdout().flush().unwrap();
    }
}

fn set_external_printer(printer: Option<Box<dyn rustyline::ExternalPrinter + Send>>) {
    let mut guard = EXTERNAL_PRINTER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = printer;
}

fn should_request_shutdown_on_readline_error(error: &rustyline::error::ReadlineError) -> bool {
    !matches!(error, rustyline::error::ReadlineError::Interrupted)
        && !matches!(error, rustyline::error::ReadlineError::WindowResized)
}

pub(crate) fn print_async_notice(agent_name: &str, msg: String) {
    clear_async_progress_notice();
    if try_print_line_via_external_printer(msg.clone()) {
        return;
    }

    print!("\r\x1b[2K");
    println!("{msg}");
    print_prompt(agent_name);
}

pub(crate) fn print_async_progress_notice(msg: String) {
    // Under rustyline, emit progress through the external printer so the editor
    // can redraw the prompt/input cleanly instead of fighting a raw carriage-
    // return progress line.
    let had_active_progress = ACTIVE_PROGRESS_LINE.swap(true, Ordering::SeqCst);
    if try_print_line_via_external_printer(if had_active_progress {
        format!("\x1b[1A\r\x1b[2K{msg}")
    } else {
        msg.clone()
    }) {
        return;
    }
    print!("\r\x1b[2K{msg}");
    std::io::stdout().flush().unwrap();
}

pub(crate) fn spawn_repl_input_task(
    line_tx: mpsc::Sender<String>,
    peers: Arc<DashMap<String, PeerInfo>>,
    direct_peer_dids: Arc<DashMap<String, bool>>,
    active_target_did: Arc<Mutex<Option<String>>>,
    active_group_target_label: Arc<Mutex<Option<String>>>,
    agent_name: String,
    disable_history: bool,
    ack_rx: std::sync::mpsc::Receiver<()>,
) {
    let headless_repl = std::env::var("QYPHA_HEADLESS")
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            s == "1" || s == "true" || s == "yes"
        })
        .unwrap_or(false);

    if headless_repl {
        println!("   {}", "Headless control channel enabled".dimmed());
        let line_tx_headless = line_tx.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;

            let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line_tx_headless
                    .send(line.trim().to_string())
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = line_tx_headless.send("/quit".to_string()).await;
        });
        return;
    }

    tokio::task::spawn_blocking(move || {
        let mut shutdown_requested = false;
        let mut request_shutdown = || {
            if !shutdown_requested {
                let _ = line_tx.blocking_send("/quit".to_string());
                shutdown_requested = true;
            }
        };
        // Privacy baseline: disable command history in all modes to avoid shell-level command traces.
        let history_size = if disable_history { 0 } else { 500 };
        let rl_config = rustyline::Config::builder()
            .max_history_size(history_size)
            .unwrap_or_default()
            .build();
        let mut rl = match rustyline::DefaultEditor::with_config(rl_config) {
            Ok(editor) => editor,
            Err(e) => {
                eprintln!("Failed to initialize line editor: {}", e);
                request_shutdown();
                return;
            }
        };
        let external_printer = rl
            .create_external_printer()
            .ok()
            .map(|printer| Box::new(printer) as Box<dyn rustyline::ExternalPrinter + Send>);
        set_external_printer(external_printer);
        let tab_cycle_triggered = Arc::new(AtomicBool::new(false));
        let tab_cycle_direction = Arc::new(AtomicI8::new(1));
        let _ = rl.bind_sequence(
            rustyline::KeyEvent(rustyline::KeyCode::Tab, rustyline::Modifiers::NONE),
            rustyline::EventHandler::Conditional(Box::new(TabCycleHandler {
                triggered: tab_cycle_triggered.clone(),
                direction: tab_cycle_direction.clone(),
                step: 1,
            })),
        );
        let _ = rl.bind_sequence(
            rustyline::KeyEvent(rustyline::KeyCode::BackTab, rustyline::Modifiers::NONE),
            rustyline::EventHandler::Conditional(Box::new(TabCycleHandler {
                triggered: tab_cycle_triggered.clone(),
                direction: tab_cycle_direction.clone(),
                step: -1,
            })),
        );

        loop {
            let active_group_label = active_group_target_label
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let (_selected_peer, prompt_peers, prompt) = if let Some(group_label) =
                active_group_label
            {
                set_active_prompt_target_label(Some(group_label.clone()));
                (
                    None,
                    Vec::new(),
                    format!(
                        "   \x1b[36m{}\x1b[0m[\x1b[33m{}\x1b[0m] > ",
                        agent_name, group_label
                    ),
                )
            } else {
                let prompt_peers = sorted_repl_peer_targets(&peers, &direct_peer_dids);
                let reconnecting_selected = selected_reconnecting_direct_peer(
                    &peers,
                    &active_target_did,
                    &direct_peer_dids,
                );
                let selected_peer = if prompt_peers.is_empty() {
                    reconnecting_selected
                } else {
                    ensure_active_repl_target(&active_target_did, &prompt_peers)
                        .or(reconnecting_selected)
                };
                let label_peers = if let Some(selected) = selected_peer.as_ref() {
                    if prompt_peers.iter().any(|peer| peer.did == selected.did) {
                        prompt_peers.clone()
                    } else {
                        vec![selected.clone()]
                    }
                } else {
                    prompt_peers.clone()
                };
                let selected_label = selected_peer
                    .as_ref()
                    .map(|peer| peer_prompt_label(peer, &label_peers));
                set_active_prompt_target_label(selected_label);
                let prompt = format_repl_prompt(&agent_name, selected_peer.as_ref(), &label_peers);
                (selected_peer, prompt_peers, prompt)
            };
            match rl.readline(&prompt) {
                Ok(line) => {
                    let trimmed = line.trim().to_string();
                    if !disable_history && !trimmed.is_empty() {
                        let _ = rl.add_history_entry(&trimmed);
                    }
                    if line_tx.blocking_send(trimmed).is_err() {
                        break;
                    }
                    let _ = ack_rx.recv();
                }
                Err(rustyline::error::ReadlineError::Interrupted) => {
                    if tab_cycle_triggered.swap(false, Ordering::SeqCst) {
                        if active_group_target_label
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .is_none()
                        {
                            let cycle_peers = if prompt_peers.is_empty() {
                                sorted_repl_peer_targets(&peers, &direct_peer_dids)
                            } else {
                                prompt_peers.clone()
                            };
                            let direction = tab_cycle_direction.swap(1, Ordering::SeqCst);
                            let _ = cycle_active_repl_target(
                                &active_target_did,
                                &cycle_peers,
                                direction,
                            );
                        }
                    }
                    continue;
                }
                Err(error) => {
                    if should_request_shutdown_on_readline_error(&error) {
                        tracing::warn!(%error, "REPL input failed — shutting down agent cleanly");
                        request_shutdown();
                        break;
                    }
                    continue;
                }
            }
        }

        set_external_printer(None);
    });
}
