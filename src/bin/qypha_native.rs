use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use eframe::egui;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

static PANIC_WIPE_TRIGGERED: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK_ONCE: Once = Once::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiSecurityPolicy {
    global: UiGlobalPolicy,
    safe: UiModePolicy,
    ghost: UiModePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiGlobalPolicy {
    screenshot_watch: bool,
    screenshot_auto_lock: bool,
    panic_wipe: bool,
    unlock_code_env: String,
    clipboard_clear_ms: u64,
    idle_poll_ms: u64,
    transfer_poll_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiModePolicy {
    mask_did: bool,
    allow_clipboard: bool,
    auto_lock_secs: u64,
    hide_runtime_logs: bool,
    wipe_on_lock: bool,
}

impl Default for UiSecurityPolicy {
    fn default() -> Self {
        Self {
            global: UiGlobalPolicy {
                screenshot_watch: true,
                screenshot_auto_lock: true,
                panic_wipe: true,
                unlock_code_env: "QYPHA_UI_UNLOCK".to_string(),
                clipboard_clear_ms: 15_000,
                idle_poll_ms: 420,
                transfer_poll_ms: 120,
            },
            safe: UiModePolicy {
                mask_did: true,
                allow_clipboard: true,
                auto_lock_secs: 300,
                hide_runtime_logs: false,
                wipe_on_lock: true,
            },
            ghost: UiModePolicy {
                mask_did: true,
                allow_clipboard: false,
                auto_lock_secs: 60,
                hide_runtime_logs: true,
                wipe_on_lock: true,
            },
        }
    }
}

impl UiSecurityPolicy {
    fn mode_policy(&self, mode: &str) -> UiModePolicy {
        match mode.to_lowercase().as_str() {
            "ghost" => self.ghost.clone(),
            _ => self.safe.clone(),
        }
    }

    fn load_or_create(path: &Path) -> Self {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(parsed) = toml::from_str::<UiSecurityPolicy>(&content) {
                return parsed;
            }
        }

        let default_policy = UiSecurityPolicy::default();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(serialized) = toml::to_string_pretty(&default_policy) {
            let _ = fs::write(path, serialized);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        default_policy
    }
}

const UI_BRIDGE_PREFIX: &str = "/ui ";

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum UiBridgeCommand {
    SendTo { selector: String, message: String },
    ConnectInvite { code: String },
    Accept { selector: String },
    Reject { selector: String },
    Block { selector: String },
    AcceptAlways { selector: String },
    AcceptAsk { selector: String },
    KickGroupMember { member_id: String },
    TransferToPeer { selector: String, path: String },
    TransferToGroup { group_id: String, path: String },
}

#[derive(Debug, Clone)]
struct AgentProfile {
    name: String,
    mode: String,
    transport: String,
    listen_port: u16,
    config_path: Option<String>,
}

#[derive(Debug, Clone)]
struct PeerRuntime {
    name: String,
    did: String,
    peer_id: Option<String>,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxGroupSnapshot {
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    #[serde(default)]
    anonymous_security_state: Option<String>,
    persistence: String,
    local_member_id: Option<String>,
    owner_member_id: Option<String>,
    owner_special_id: Option<String>,
    known_member_ids: Vec<String>,
    mailbox_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupMailboxRuntimeEvent {
    kind: String,
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    manifest_id: Option<String>,
    sender_member_id: Option<String>,
    message: Option<String>,
    filename: Option<String>,
    size_bytes: Option<u64>,
    member_id: Option<String>,
    member_display_name: Option<String>,
    invite_code: Option<String>,
    mailbox_epoch: Option<u64>,
    kicked_member_id: Option<String>,
    #[serde(default)]
    ts_ms: i64,
}

#[derive(Debug, Clone)]
struct ChatMessage {
    direction: MessageDirection,
    sender: String,
    text: String,
}

#[derive(Debug, Clone)]
struct PendingGroupFileOffer {
    manifest_id: String,
    group_id: String,
    group_name: Option<String>,
    anonymous_group: bool,
    sender_member_id: Option<String>,
    filename: Option<String>,
    size_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
struct PendingGroupHandshakeOffer {
    sender_member_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConversationType {
    Group,
    Dm,
}

#[derive(Debug, Clone)]
struct Conversation {
    key: String,
    ctype: ConversationType,
    title: String,
    did: Option<String>,
    messages: Vec<ChatMessage>,
}

impl Conversation {
    fn group(group_id: &str, title: &str) -> Self {
        Self {
            key: group_conversation_key(group_id),
            ctype: ConversationType::Group,
            title: title.to_string(),
            did: None,
            messages: Vec::new(),
        }
    }
}

struct RuntimeProcess {
    child: Child,
    stdin: ChildStdin,
}

#[derive(Default)]
struct TransferContext {
    outgoing_did: Option<String>,
}

struct AgentRuntime {
    name: String,
    mode: String,
    transport: String,
    listen_port: u16,
    config_path: Option<String>,

    process: Option<RuntimeProcess>,
    started_at: Option<String>,
    last_error: Option<String>,

    logs: VecDeque<String>,
    peers: HashMap<String, PeerRuntime>,
    mailbox_groups: BTreeMap<String, MailboxGroupSnapshot>,
    pending_mailbox_groups: Vec<MailboxGroupSnapshot>,
    mailbox_group_refreshing: bool,
    pending_approvals: HashSet<String>,
    group_events: VecDeque<GroupMailboxRuntimeEvent>,

    pending_connected_peer_id: Option<String>,
    pending_verbose_name: Option<String>,
    pending_verbose_did: Option<String>,
    pending_verbose_peer_id: Option<String>,

    selected_peer: Option<String>,
    conversations: HashMap<String, Conversation>,
    active_conversation: String,
    sender_did_cache: HashMap<String, String>,
    deleted_dids: HashSet<String>,

    transfer_ctx: TransferContext,
    last_peer_refresh_at: Instant,
}

impl Default for AgentRuntime {
    fn default() -> Self {
        Self {
            name: String::new(),
            mode: "safe".to_string(),
            transport: "internet".to_string(),
            listen_port: 9090,
            config_path: None,
            process: None,
            started_at: None,
            last_error: None,
            logs: VecDeque::new(),
            peers: HashMap::new(),
            mailbox_groups: BTreeMap::new(),
            pending_mailbox_groups: Vec::new(),
            mailbox_group_refreshing: false,
            pending_approvals: HashSet::new(),
            group_events: VecDeque::new(),
            pending_connected_peer_id: None,
            pending_verbose_name: None,
            pending_verbose_did: None,
            pending_verbose_peer_id: None,
            selected_peer: None,
            conversations: HashMap::new(),
            active_conversation: String::new(),
            sender_did_cache: HashMap::new(),
            deleted_dids: HashSet::new(),
            transfer_ctx: TransferContext::default(),
            last_peer_refresh_at: Instant::now(),
        }
    }
}

impl AgentRuntime {
    fn is_running(&mut self) -> bool {
        if let Some(proc) = self.process.as_mut() {
            if let Ok(Some(status)) = proc.child.try_wait() {
                self.last_error = Some(format!("runtime exited with status {}", status));
                self.process = None;
            }
        }
        self.process.is_some()
    }

    fn ensure_dm_conversation(&mut self, did: &str, fallback_name: &str) -> String {
        let key = format!("dm:{}", did);
        if !self.conversations.contains_key(&key) {
            self.conversations.insert(
                key.clone(),
                Conversation {
                    key: key.clone(),
                    ctype: ConversationType::Dm,
                    title: fallback_name.to_string(),
                    did: Some(did.to_string()),
                    messages: Vec::new(),
                },
            );
        }
        key
    }

    fn ensure_group_conversation(&mut self, group_id: &str, fallback_title: &str) -> String {
        let key = group_conversation_key(group_id);
        if !self.conversations.contains_key(&key) {
            self.conversations
                .insert(key.clone(), Conversation::group(group_id, fallback_title));
        } else if let Some(conv) = self.conversations.get_mut(&key) {
            conv.title = fallback_title.to_string();
        }
        key
    }

    fn sync_group_conversations(&mut self) {
        let mailbox_groups: Vec<MailboxGroupSnapshot> =
            self.mailbox_groups.values().cloned().collect();
        let valid_keys: HashSet<String> = mailbox_groups
            .iter()
            .map(|group| group_conversation_key(&group.group_id))
            .collect();

        self.conversations.retain(|key, conv| {
            if conv.ctype != ConversationType::Group {
                return true;
            }
            valid_keys.contains(key)
        });

        for group in mailbox_groups {
            let title = mailbox_group_label(&group);
            self.ensure_group_conversation(&group.group_id, &title);
        }

        if self.active_conversation.is_empty()
            || !self.conversations.contains_key(&self.active_conversation)
        {
            self.active_conversation = self
                .conversations
                .values()
                .filter(|conv| conv.ctype == ConversationType::Group)
                .map(|conv| conv.key.clone())
                .next()
                .or_else(|| {
                    self.conversations
                        .values()
                        .map(|conv| conv.key.clone())
                        .next()
                })
                .unwrap_or_default();
        }
    }

    fn append_message(&mut self, key: &str, msg: ChatMessage) {
        if let Some(conv) = self.conversations.get_mut(key) {
            conv.messages.push(msg);
            if conv.messages.len() > 400 {
                conv.messages.remove(0);
            }
        }
    }
}

fn looks_like_group_id(value: &str) -> bool {
    let raw = value.trim();
    !raw.is_empty()
        && (raw.starts_with("grp_") || raw.starts_with("gmbx_") || raw.starts_with("group:"))
        && raw
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':'))
}

fn group_conversation_key(group_id: &str) -> String {
    format!("group:{}", group_id)
}

fn group_id_from_conversation_key(key: &str) -> Option<String> {
    let raw = key.trim();
    let group_id = raw.strip_prefix("group:")?;
    looks_like_group_id(group_id).then(|| group_id.to_string())
}

fn mailbox_group_label(group: &MailboxGroupSnapshot) -> String {
    group
        .group_name
        .clone()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| group.group_id.clone())
}

fn mailbox_group_member_count(group: &MailboxGroupSnapshot) -> usize {
    let mut unique_members: HashSet<String> = group.known_member_ids.iter().cloned().collect();
    if let Some(local_member_id) = group.local_member_id.as_ref() {
        unique_members.insert(local_member_id.clone());
    }
    unique_members.len()
}

fn mailbox_group_summary(group: &MailboxGroupSnapshot) -> String {
    if group.anonymous_group {
        let security = match group.anonymous_security_state.as_deref() {
            Some("v2_secure") => "v2 secure",
            Some("legacy") => "legacy",
            _ => "anonymous",
        };
        format!("tor mailbox • {} • epoch {}", security, group.mailbox_epoch)
    } else {
        format!(
            "tor mailbox • epoch {} • {} members",
            group.mailbox_epoch,
            mailbox_group_member_count(group)
        )
    }
}

#[derive(Debug)]
enum UiEvent {
    RuntimeLine { agent: String, line: String },
    RuntimeStreamClosed { agent: String },
    ScreenshotDetected { path: String },
}

#[derive(Default)]
struct UiForm {
    agent_name: String,
    transport: String,
    log_mode: String,
    listen_port: u16,
    passphrase: String,
    config_path: String,
    message_input: String,
    transfer_path: String,
    connect_code: String,
    group_name: String,
    unlock_code: String,
}

#[derive(Clone)]
struct PendingDelete {
    agent: String,
    conversation_key: String,
    label: String,
}

struct QyphaNativeApp {
    root: PathBuf,
    policy_path: PathBuf,
    policy: UiSecurityPolicy,

    tx: Sender<UiEvent>,
    rx: Receiver<UiEvent>,
    screenshot_watcher: Option<RecommendedWatcher>,

    profiles: BTreeMap<String, AgentProfile>,
    runtimes: HashMap<String, AgentRuntime>,
    active_agent: Option<String>,

    form: UiForm,
    feedback: String,
    feedback_error: bool,

    latest_invite_code: String,
    latest_group_invite_code: String,

    pending_delete: Option<PendingDelete>,
    open_menu_key: Option<String>,

    ui_locked: bool,
    lock_reason: String,
    unlock_required: Option<String>,
    last_interaction: Instant,

    clipboard_deadline: Option<Instant>,
}

#[derive(Debug, Deserialize)]
struct AgentToml {
    agent: Option<AgentTomlAgent>,
    network: Option<AgentTomlNetwork>,
    security: Option<AgentTomlSecurity>,
    logging: Option<AgentTomlLogging>,
}

#[derive(Debug, Deserialize)]
struct AgentTomlAgent {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentTomlNetwork {
    listen_port: Option<u16>,
    transport_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentTomlSecurity {
    log_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentTomlLogging {
    mode: Option<String>,
}

impl QyphaNativeApp {
    fn new() -> Self {
        let root = workspace_root();
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let policy_path = PathBuf::from(home).join(".qypha").join("ui_policy.toml");
        let policy = UiSecurityPolicy::load_or_create(&policy_path);

        let (tx, rx) = mpsc::channel();
        let unlock_required = if !policy.global.unlock_code_env.trim().is_empty() {
            std::env::var(policy.global.unlock_code_env.as_str())
                .ok()
                .filter(|v| !v.trim().is_empty())
        } else {
            None
        };

        let mut app = Self {
            root,
            policy_path,
            policy,
            tx,
            rx,
            screenshot_watcher: None,
            profiles: BTreeMap::new(),
            runtimes: HashMap::new(),
            active_agent: None,
            form: UiForm {
                agent_name: "a".to_string(),
                transport: "internet".to_string(),
                log_mode: "safe".to_string(),
                listen_port: 9090,
                passphrase: String::new(),
                config_path: String::new(),
                message_input: String::new(),
                transfer_path: String::new(),
                connect_code: String::new(),
                group_name: String::new(),
                unlock_code: String::new(),
            },
            feedback: String::new(),
            feedback_error: false,
            latest_invite_code: String::new(),
            latest_group_invite_code: String::new(),
            pending_delete: None,
            open_menu_key: None,
            ui_locked: false,
            lock_reason: String::new(),
            unlock_required,
            last_interaction: Instant::now(),
            clipboard_deadline: None,
        };

        app.refresh_profiles();
        app.sync_form_with_active_profile();
        app.install_panic_hook();
        app.start_screenshot_watch_if_enabled();
        app
    }

    fn install_panic_hook(&self) {
        if !self.policy.global.panic_wipe {
            return;
        }
        PANIC_HOOK_ONCE.call_once(|| {
            std::panic::set_hook(Box::new(|_info| {
                PANIC_WIPE_TRIGGERED.store(true, Ordering::SeqCst);
                best_effort_clear_clipboard();
            }));
        });
    }

    fn start_screenshot_watch_if_enabled(&mut self) {
        if !self.policy.global.screenshot_watch {
            return;
        }
        let Some(home) = std::env::var("HOME").ok() else {
            return;
        };
        let desktop = PathBuf::from(home).join("Desktop");
        if !desktop.exists() {
            return;
        }

        let tx = self.tx.clone();
        let watcher_res = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                for path in event.paths {
                    if looks_like_screenshot_path(&path) {
                        let _ = tx.send(UiEvent::ScreenshotDetected {
                            path: path.display().to_string(),
                        });
                    }
                }
            }
        });

        if let Ok(mut watcher) = watcher_res {
            if watcher.watch(&desktop, RecursiveMode::NonRecursive).is_ok() {
                self.screenshot_watcher = Some(watcher);
            }
        }
    }

    fn refresh_profiles(&mut self) {
        let discovered = discover_agent_profiles(&self.root);
        self.profiles.clear();
        for p in discovered {
            self.profiles.insert(p.name.clone(), p.clone());
            let rt = self.runtimes.entry(p.name.clone()).or_default();
            rt.name = p.name.clone();
            rt.mode = p.mode.clone();
            rt.transport = p.transport.clone();
            rt.listen_port = p.listen_port;
            rt.config_path = p.config_path.clone();
        }
        if self.active_agent.is_none() {
            self.active_agent = self.profiles.keys().next().cloned();
        }
    }

    fn sync_form_with_active_profile(&mut self) {
        if let Some(active) = self.active_agent.clone() {
            if let Some(profile) = self.profiles.get(&active) {
                self.form.agent_name = profile.name.clone();
                self.form.transport = profile.transport.clone();
                self.form.log_mode = profile.mode.clone();
                self.form.listen_port = profile.listen_port;
                self.form.config_path = profile
                    .config_path
                    .clone()
                    .unwrap_or_else(|| derived_config_path(&self.root, &profile.name));
                self.enforce_form_transport_constraints();
                return;
            }
        }
        self.form.config_path = derived_config_path(&self.root, &self.form.agent_name);
        self.enforce_form_transport_constraints();
    }

    fn enforce_form_transport_constraints(&mut self) {
        let normalized_mode =
            normalized_log_mode_for_transport(&self.form.transport, &self.form.log_mode);
        if self.form.log_mode != normalized_mode {
            self.form.log_mode = normalized_mode;
        }
        if self.form.log_mode.eq_ignore_ascii_case("ghost") {
            self.form.config_path.clear();
        } else if self.form.config_path.trim().is_empty() {
            self.form.config_path = derived_config_path(&self.root, &self.form.agent_name);
        }
    }

    fn set_feedback(&mut self, message: impl Into<String>, error: bool) {
        self.feedback = message.into();
        self.feedback_error = error;
    }

    fn clear_feedback(&mut self) {
        self.feedback.clear();
        self.feedback_error = false;
    }

    fn active_runtime_mut(&mut self) -> Option<&mut AgentRuntime> {
        let active = self.active_agent.clone()?;
        self.runtimes.get_mut(&active)
    }

    fn active_runtime(&self) -> Option<&AgentRuntime> {
        let active = self.active_agent.as_ref()?;
        self.runtimes.get(active)
    }

    fn effective_mode_policy(&self) -> UiModePolicy {
        if let Some(rt) = self.active_runtime() {
            return self.policy.mode_policy(&rt.mode);
        }
        self.policy.mode_policy(&self.form.log_mode)
    }

    fn lock_ui(&mut self, reason: impl Into<String>) {
        self.ui_locked = true;
        self.lock_reason = reason.into();
        if self.effective_mode_policy().wipe_on_lock {
            self.clear_sensitive_ui_memory();
        }
    }

    fn unlock_ui(&mut self) {
        self.ui_locked = false;
        self.lock_reason.clear();
        self.form.unlock_code.zeroize();
        self.form.unlock_code.clear();
        self.last_interaction = Instant::now();
    }

    fn clear_sensitive_ui_memory(&mut self) {
        self.form.message_input.zeroize();
        self.form.message_input.clear();
        self.form.transfer_path.zeroize();
        self.form.transfer_path.clear();
        self.form.connect_code.zeroize();
        self.form.connect_code.clear();
        self.form.passphrase.zeroize();
        self.form.passphrase.clear();

        self.latest_invite_code.zeroize();
        self.latest_invite_code.clear();
        self.latest_group_invite_code.zeroize();
        self.latest_group_invite_code.clear();

        for rt in self.runtimes.values_mut() {
            for conv in rt.conversations.values_mut() {
                for msg in &mut conv.messages {
                    msg.text.zeroize();
                    msg.text.clear();
                }
                conv.messages.clear();
            }
            rt.logs.clear();
        }
        best_effort_clear_clipboard();
    }

    fn process_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                UiEvent::RuntimeLine { agent, line } => {
                    if let Some(rt) = self.runtimes.get_mut(&agent) {
                        ingest_runtime_line(rt, line.clone());
                        apply_chat_line(rt, &line);
                        refresh_invite_codes(
                            rt,
                            &mut self.latest_invite_code,
                            &mut self.latest_group_invite_code,
                        );
                    }
                }
                UiEvent::RuntimeStreamClosed { agent } => {
                    if let Some(rt) = self.runtimes.get_mut(&agent) {
                        if rt.is_running() {
                            // stream close can occur during restart; keep state
                        }
                    }
                }
                UiEvent::ScreenshotDetected { path } => {
                    if self.policy.global.screenshot_auto_lock {
                        self.lock_ui(format!("Screenshot activity detected: {}", path));
                    } else {
                        self.set_feedback(format!("Screenshot detected: {}", path), true);
                    }
                }
            }
        }
    }

    fn tick_runtime_health(&mut self) {
        let active_mode_policy = self.effective_mode_policy();
        let idle_ms = self.policy.global.idle_poll_ms.max(80);
        let transfer_ms = self.policy.global.transfer_poll_ms.max(50);

        for rt in self.runtimes.values_mut() {
            let running = rt.is_running();
            if !running {
                continue;
            }
            let poll_ms = if has_active_transfer(&rt.logs) {
                transfer_ms
            } else {
                idle_ms
            };
            if rt.last_peer_refresh_at.elapsed() >= Duration::from_millis(poll_ms.max(350)) {
                let _ = send_line(rt, "/peers", false);
                let _ = send_line(rt, "/groups", false);
                rt.last_peer_refresh_at = Instant::now();
            }
        }

        if active_mode_policy.auto_lock_secs > 0
            && self.last_interaction.elapsed().as_secs() >= active_mode_policy.auto_lock_secs
        {
            self.lock_ui("Auto-lock due to inactivity");
        }

        if PANIC_WIPE_TRIGGERED.load(Ordering::SeqCst) {
            self.clear_sensitive_ui_memory();
            self.lock_ui("Panic wipe triggered");
        }

        if let Some(deadline) = self.clipboard_deadline {
            if Instant::now() >= deadline {
                best_effort_clear_clipboard();
                self.clipboard_deadline = None;
            }
        }
    }

    fn create_agent(&mut self) {
        const MIN_SAFE_PASSPHRASE_LEN: usize = 4;
        self.enforce_form_transport_constraints();
        if self.form.agent_name.trim().is_empty() {
            self.set_feedback("Agent name is required", true);
            return;
        }
        if self.form.log_mode.eq_ignore_ascii_case("ghost") {
            self.set_feedback("Ghost mode does not create persistent agents", true);
            return;
        }
        if self.form.passphrase.trim().len() < MIN_SAFE_PASSPHRASE_LEN {
            self.set_feedback("Passphrase too short (min 4)", true);
            return;
        }

        let mut args = vec![
            "init".to_string(),
            "--name".to_string(),
            self.form.agent_name.trim().to_string(),
            "--transport".to_string(),
            self.form.transport.trim().to_string(),
            "--log-mode".to_string(),
            self.form.log_mode.trim().to_string(),
            "--port".to_string(),
            self.form.listen_port.to_string(),
        ];

        let mut cmd = build_qypha_command(&self.root, &mut args);
        cmd.current_dir(&self.root)
            .env("QYPHA_INIT_PASSPHRASE", self.form.passphrase.clone())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        match cmd.output() {
            Ok(output) if output.status.success() => {
                self.set_feedback(
                    format!("Agent '{}' initialized", self.form.agent_name.trim()),
                    false,
                );
                self.refresh_profiles();
                self.active_agent = Some(self.form.agent_name.trim().to_string());
                self.sync_form_with_active_profile();
            }
            Ok(output) => {
                let out = String::from_utf8_lossy(&output.stdout);
                let err = String::from_utf8_lossy(&output.stderr);
                self.set_feedback(format!("Init failed\n{}\n{}", out.trim(), err.trim()), true);
            }
            Err(e) => {
                self.set_feedback(format!("Init spawn failed: {}", e), true);
            }
        }
    }

    fn start_runtime(&mut self) {
        self.enforce_form_transport_constraints();
        let agent_name = self.form.agent_name.trim().to_string();
        if agent_name.is_empty() {
            self.set_feedback("Agent name is required", true);
            return;
        }

        let mode = self.form.log_mode.trim().to_lowercase();
        let transport = self.form.transport.trim().to_lowercase();
        if mode == "ghost" && transport != "tor" {
            self.set_feedback("Ghost mode requires tor transport", true);
            return;
        }

        let rt = self.runtimes.entry(agent_name.clone()).or_default();
        if rt.is_running() {
            self.set_feedback("Runtime already running", true);
            return;
        }

        rt.name = agent_name.clone();
        rt.mode = mode.clone();
        rt.transport = transport.clone();
        rt.listen_port = self.form.listen_port;
        rt.config_path = if mode == "ghost" {
            None
        } else {
            Some(self.form.config_path.clone())
        };

        let mut args = if mode == "ghost" {
            vec![
                "launch".to_string(),
                "--name".to_string(),
                agent_name.clone(),
                "--transport".to_string(),
                "tor".to_string(),
                "--log-mode".to_string(),
                "ghost".to_string(),
                "--port".to_string(),
                self.form.listen_port.to_string(),
            ]
        } else {
            if self.form.config_path.trim().is_empty() {
                self.set_feedback("Config path is required for safe mode", true);
                return;
            }
            if self.form.passphrase.trim().is_empty() {
                self.set_feedback("Passphrase is required for safe mode", true);
                return;
            }
            vec![
                "start".to_string(),
                "--config".to_string(),
                resolve_config_path(&self.root, self.form.config_path.trim())
                    .display()
                    .to_string(),
                "--transport".to_string(),
                transport.clone(),
                "--log-mode".to_string(),
                mode.clone(),
                "--port".to_string(),
                self.form.listen_port.to_string(),
            ]
        };

        let mut cmd = build_qypha_command(&self.root, &mut args);
        cmd.current_dir(&self.root)
            .env("QYPHA_HEADLESS", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::piped());
        if mode != "ghost" {
            cmd.env("QYPHA_PASSPHRASE", self.form.passphrase.clone());
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                let stdin = child.stdin.take();
                let Some(stdin) = stdin else {
                    self.set_feedback("Runtime stdin unavailable", true);
                    return;
                };
                let process = RuntimeProcess { child, stdin };

                rt.process = Some(process);
                rt.started_at = Some(Utc::now().to_rfc3339());
                rt.last_error = None;
                rt.logs.clear();
                rt.peers.clear();
                rt.mailbox_groups.clear();
                rt.pending_mailbox_groups.clear();
                rt.mailbox_group_refreshing = false;
                rt.group_events.clear();
                rt.conversations.clear();
                rt.active_conversation.clear();
                rt.pending_approvals.clear();
                rt.selected_peer = None;
                rt.last_peer_refresh_at = Instant::now();
                push_log(rt, "[qypha-native] runtime started".to_string());

                if let Some(out) = stdout {
                    spawn_line_reader(out, agent_name.clone(), self.tx.clone());
                }
                if let Some(err) = stderr {
                    spawn_line_reader(err, agent_name.clone(), self.tx.clone());
                }

                self.active_agent = Some(agent_name.clone());
                self.refresh_profiles();
                self.set_feedback(
                    format!(
                        "Agent '{}' started. Invite üretmeden önce birkaç saniye bekleyin.",
                        agent_name
                    ),
                    false,
                );
            }
            Err(e) => {
                self.set_feedback(format!("Start failed: {}", e), true);
            }
        }
    }

    fn stop_runtime(&mut self) {
        let Some(active) = self.active_agent.clone() else {
            self.set_feedback("No active agent selected", true);
            return;
        };
        if let Some(rt) = self.runtimes.get_mut(&active) {
            if !rt.is_running() {
                self.set_feedback("Runtime already offline", false);
                return;
            }
            let was_ghost = rt.mode.eq_ignore_ascii_case("ghost");
            let _ = send_line(rt, "/quit", true);
            if let Some(proc) = rt.process.as_mut() {
                let _ = proc.child.kill();
            }
            rt.process = None;
            rt.pending_approvals.clear();
            rt.group_events.clear();
            rt.selected_peer = None;
            push_log(rt, "[qypha-native] runtime stopped".to_string());
            if was_ghost {
                self.clear_sensitive_ui_memory();
                self.ui_locked = false;
            }
            self.set_feedback(format!("Agent '{}' stopped", active), false);
        }
    }

    fn copy_text(&mut self, ctx: &egui::Context, value: &str, label: &str) {
        let mode = self.effective_mode_policy();
        if !mode.allow_clipboard {
            self.set_feedback("Clipboard is disabled by current policy", true);
            return;
        }
        if value.trim().is_empty() {
            self.set_feedback(format!("{} is empty", label), true);
            return;
        }
        ctx.copy_text(value.to_string());
        best_effort_copy_to_os_clipboard(value);
        if self.policy.global.clipboard_clear_ms > 0 {
            self.clipboard_deadline =
                Some(Instant::now() + Duration::from_millis(self.policy.global.clipboard_clear_ms));
        }
        self.set_feedback(format!("{} copied", label), false);
    }

    fn generate_invite(&mut self, group: bool) {
        let group_name = self.form.group_name.trim().to_string();
        if group && group_name.is_empty() {
            self.set_feedback("Group name is required", true);
            return;
        }
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        if !rt.is_running() {
            self.set_feedback("Runtime is offline", true);
            return;
        }
        let command = if group {
            if rt.mode.eq_ignore_ascii_case("ghost") {
                format!("/group_anon {}", group_name)
            } else {
                format!("/group_normal {}", group_name)
            }
        } else {
            "/invite".to_string()
        };
        if let Err(e) = send_line(rt, &command, true) {
            self.set_feedback(e, true);
            return;
        }
        self.set_feedback(
            if group {
                "Generating new mailbox group invite..."
            } else {
                "Generating new /invite..."
            },
            false,
        );
    }

    fn regenerate_mailbox_group_invite(&mut self, group_id: &str) {
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        if !rt.is_running() {
            self.set_feedback("Runtime is offline", true);
            return;
        }
        let group_id = group_id.trim();
        if group_id.is_empty() {
            self.set_feedback("Group id is required", true);
            return;
        }
        let Some(group) = rt.mailbox_groups.get(group_id).cloned() else {
            self.set_feedback(format!("Unknown mailbox group '{}'", group_id), true);
            return;
        };
        let command = if group.anonymous_group {
            let Some(owner_special_id) = group.owner_special_id.as_ref() else {
                self.set_feedback(
                    format!(
                        "Anonymous mailbox group '{}' is missing owner handle",
                        group_id
                    ),
                    true,
                );
                return;
            };
            format!("/invite_anon {}", owner_special_id)
        } else {
            format!("/invite_g {}", group.group_id)
        };
        if let Err(e) = send_line(rt, &command, true) {
            self.set_feedback(e, true);
            return;
        }
        self.set_feedback(
            if group.anonymous_group {
                "Rotating ghost invite to a fresh epoch. Older invites will become invalid..."
            } else {
                "Refreshing mailbox group invite..."
            },
            false,
        );
    }

    fn connect_invite(&mut self) {
        let code = normalize_invite_code(&self.form.connect_code);
        if code.is_empty() {
            self.set_feedback("Invite code is empty", true);
            return;
        }
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        if let Err(e) = send_ui_bridge_command(
            rt,
            UiBridgeCommand::ConnectInvite {
                code: code.to_string(),
            },
        ) {
            self.set_feedback(e, true);
            return;
        }
        self.form.connect_code.zeroize();
        self.form.connect_code.clear();
    }

    fn send_message(&mut self) {
        let message = self.form.message_input.trim().to_string();
        if message.is_empty() {
            return;
        }
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        if !rt.is_running() {
            self.set_feedback("Runtime is offline", true);
            return;
        }

        let active_key = rt.active_conversation.clone();
        if let Some(group_id) = group_id_from_conversation_key(&active_key) {
            if let Err(e) = send_ui_bridge_command(
                rt,
                UiBridgeCommand::SendTo {
                    selector: group_id.clone(),
                    message: message.clone(),
                },
            ) {
                self.set_feedback(e, true);
                return;
            }
            let title = rt
                .mailbox_groups
                .get(&group_id)
                .map(mailbox_group_label)
                .unwrap_or_else(|| group_id.clone());
            let key = rt.ensure_group_conversation(&group_id, &title);
            rt.append_message(
                &key,
                ChatMessage {
                    direction: MessageDirection::Out,
                    sender: "you".to_string(),
                    text: message,
                },
            );
        } else if let Some(conv) = rt.conversations.get(&active_key) {
            if let Some(did) = conv.did.clone() {
                if let Err(e) = send_ui_bridge_command(
                    rt,
                    UiBridgeCommand::SendTo {
                        selector: did.clone(),
                        message: message.clone(),
                    },
                ) {
                    self.set_feedback(e, true);
                    return;
                }
                rt.append_message(
                    &active_key,
                    ChatMessage {
                        direction: MessageDirection::Out,
                        sender: "you".to_string(),
                        text: message,
                    },
                );
                rt.selected_peer = Some(did);
            }
        }

        self.form.message_input.zeroize();
        self.form.message_input.clear();
    }

    fn send_transfer(&mut self) {
        let path = self.form.transfer_path.trim().to_string();
        if path.is_empty() {
            self.set_feedback("Transfer path is empty", true);
            return;
        }

        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };

        if has_outgoing_transfer(&rt.logs) {
            self.set_feedback("Another outgoing transfer is already in progress", true);
            return;
        }

        let active_key = rt.active_conversation.clone();
        if let Some(group_id) = group_id_from_conversation_key(&active_key) {
            if let Err(e) = send_ui_bridge_command(
                rt,
                UiBridgeCommand::TransferToGroup {
                    group_id: group_id.clone(),
                    path: path.clone(),
                },
            ) {
                self.set_feedback(e, true);
                return;
            }
            let title = rt
                .mailbox_groups
                .get(&group_id)
                .map(mailbox_group_label)
                .unwrap_or_else(|| group_id.clone());
            let key = rt.ensure_group_conversation(&group_id, &title);
            let file_label = Path::new(&path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(path.as_str())
                .to_string();
            rt.append_message(
                &key,
                ChatMessage {
                    direction: MessageDirection::Out,
                    sender: "system".to_string(),
                    text: format!("shared file • {}", file_label),
                },
            );
            return;
        }

        let Some(conv) = rt.conversations.get(&active_key) else {
            self.set_feedback("No active conversation", true);
            return;
        };
        let Some(did) = conv.did.clone() else {
            self.set_feedback("Transfer requires an active DM", true);
            return;
        };

        if let Err(e) = send_ui_bridge_command(
            rt,
            UiBridgeCommand::TransferToPeer {
                selector: did.clone(),
                path: path.clone(),
            },
        ) {
            self.set_feedback(e, true);
            return;
        }
        rt.transfer_ctx.outgoing_did = Some(did);
    }

    fn transfer_decision(&mut self, action: &str, did: &str) {
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        let cmd = match action {
            "accept" => UiBridgeCommand::Accept {
                selector: did.to_string(),
            },
            "reject" => UiBridgeCommand::Reject {
                selector: did.to_string(),
            },
            "always" => UiBridgeCommand::AcceptAlways {
                selector: did.to_string(),
            },
            "ask" => UiBridgeCommand::AcceptAsk {
                selector: did.to_string(),
            },
            _ => return,
        };
        if let Err(e) = send_ui_bridge_command(rt, cmd) {
            self.set_feedback(e, true);
            return;
        }
    }

    fn group_file_offer_decision(&mut self, action: &str, manifest_id: &str) {
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        let manifest_id = manifest_id.trim();
        if manifest_id.is_empty() {
            self.set_feedback("Manifest id is required", true);
            return;
        }
        let cmd = match action {
            "accept" => UiBridgeCommand::Accept {
                selector: manifest_id.to_string(),
            },
            "reject" => UiBridgeCommand::Reject {
                selector: manifest_id.to_string(),
            },
            _ => return,
        };
        if let Err(e) = send_ui_bridge_command(rt, cmd) {
            self.set_feedback(e, true);
            return;
        }
    }

    fn group_handshake_offer_decision(&mut self, action: &str, sender_member_id: &str) {
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        let sender_member_id = sender_member_id.trim();
        if sender_member_id.is_empty() {
            self.set_feedback("Sender member ID is required", true);
            return;
        }
        rt.group_events
            .retain(|event| event.sender_member_id.as_deref() != Some(sender_member_id));
        let cmd = match action {
            "accept" => UiBridgeCommand::Accept {
                selector: sender_member_id.to_string(),
            },
            "reject" => UiBridgeCommand::Reject {
                selector: sender_member_id.to_string(),
            },
            "block" => UiBridgeCommand::Block {
                selector: sender_member_id.to_string(),
            },
            _ => return,
        };
        if let Err(e) = send_ui_bridge_command(rt, cmd) {
            self.set_feedback(e, true);
            return;
        }
        let feedback = match action {
            "accept" => "Direct trust offer accepted via secure direct-connect flow",
            "reject" => "Direct trust offer rejected",
            "block" => "Direct trust sender blocked",
            _ => return,
        };
        self.set_feedback(feedback, false);
    }

    fn kick_group_member(&mut self, member_id: &str) {
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        let member_id = member_id.trim();
        if member_id.is_empty() {
            self.set_feedback("Member ID is required", true);
            return;
        }
        if let Err(e) = send_ui_bridge_command(
            rt,
            UiBridgeCommand::KickGroupMember {
                member_id: member_id.to_string(),
            },
        ) {
            self.set_feedback(e, true);
            return;
        }
        self.set_feedback(
            format!("Mailbox rotation requested for {}", member_id),
            false,
        );
    }

    fn delete_conversation(&mut self, key: &str) {
        let Some(rt) = self.active_runtime_mut() else {
            return;
        };
        if group_id_from_conversation_key(key).is_some() {
            return;
        }
        let did = rt
            .conversations
            .get(key)
            .and_then(|c| c.did.clone())
            .unwrap_or_default();
        rt.conversations.remove(key);
        if !did.is_empty() {
            rt.deleted_dids.insert(did.clone());
            rt.sender_did_cache.retain(|_, v| v != &did);
            if rt.selected_peer.as_deref() == Some(did.as_str()) {
                rt.selected_peer = None;
            }
            if rt.transfer_ctx.outgoing_did.as_deref() == Some(did.as_str()) {
                rt.transfer_ctx.outgoing_did = None;
            }
        }
        if rt.active_conversation == key {
            rt.active_conversation = rt
                .conversations
                .values()
                .filter(|conv| conv.ctype == ConversationType::Group)
                .map(|conv| conv.key.clone())
                .next()
                .unwrap_or_default();
        }
    }

    fn open_mailbox_group(&mut self, group_id: &str) {
        let Some(rt) = self.active_runtime_mut() else {
            self.set_feedback("No active runtime", true);
            return;
        };
        let group_id = group_id.trim();
        if group_id.is_empty() {
            self.set_feedback("Group id is required", true);
            return;
        }
        let Some(group) = rt.mailbox_groups.get(group_id).cloned() else {
            self.set_feedback(format!("Unknown mailbox group '{}'", group_id), true);
            return;
        };
        let title = mailbox_group_label(&group);
        let key = rt.ensure_group_conversation(&group.group_id, &title);
        rt.active_conversation = key;
        rt.selected_peer = None;
        self.set_feedback(format!("Opened {}", title), false);
    }

    fn select_conversation(&mut self, key: &str) {
        if let Some(rt) = self.active_runtime_mut() {
            if rt.conversations.contains_key(key) {
                rt.active_conversation = key.to_string();
                if let Some(did) = rt.conversations.get(key).and_then(|c| c.did.clone()) {
                    rt.deleted_dids.remove(&did);
                    rt.selected_peer = Some(did);
                } else {
                    rt.selected_peer = None;
                }
            }
        }
    }

    fn select_peer_as_dm(&mut self, did: &str, name: &str) {
        if let Some(rt) = self.active_runtime_mut() {
            rt.deleted_dids.remove(did);
            let key = rt.ensure_dm_conversation(did, name);
            rt.active_conversation = key;
            rt.selected_peer = Some(did.to_string());
        }
    }

    fn draw_lock_screen(&mut self, ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(egui::Color32::from_rgb(234, 246, 255));
        visuals.panel_fill = egui::Color32::from_rgb(3, 9, 20);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(8, 20, 38);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(12, 36, 66);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(20, 56, 97);
        ctx.set_visuals(visuals);

        egui::CentralPanel::default().show(ctx, |ui| {
            let pulse = ((ctx.input(|i| i.time) as f32) * 1.1).sin() * 0.5 + 0.5;
            let rect = ui.max_rect();
            let painter = ui.painter_at(rect);
            painter.rect_filled(rect, 0.0, egui::Color32::from_rgb(3, 8, 18));
            painter.circle_filled(
                rect.left_top() + egui::vec2(120.0, 120.0),
                220.0,
                egui::Color32::from_rgba_unmultiplied(35, 115, 220, (24.0 + pulse * 26.0) as u8),
            );
            painter.circle_filled(
                rect.right_bottom() - egui::vec2(160.0, 140.0),
                260.0,
                egui::Color32::from_rgba_unmultiplied(44, 196, 176, (20.0 + pulse * 22.0) as u8),
            );

            ui.vertical_centered(|ui| {
                ui.add_space(90.0);
                egui::Frame::none()
                    .fill(egui::Color32::from_rgba_unmultiplied(7, 18, 35, 232))
                    .stroke(egui::Stroke::new(
                        1.2,
                        egui::Color32::from_rgb(44, 132, 215),
                    ))
                    .rounding(egui::Rounding::same(18.0))
                    .inner_margin(egui::Margin::symmetric(24.0, 20.0))
                    .show(ui, |ui| {
                        ui.set_max_width(560.0);
                        ui.vertical_centered(|ui| {
                            ui.heading("Qypha Secure Lock");
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new(self.lock_reason.clone())
                                    .color(egui::Color32::from_rgb(170, 203, 236)),
                            );
                            ui.add_space(10.0);

                            if self.unlock_required.is_some() {
                                ui.label(
                                    egui::RichText::new("Unlock code required")
                                        .color(egui::Color32::from_rgb(147, 184, 220)),
                                );
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.form.unlock_code)
                                        .password(true)
                                        .desired_width(280.0)
                                        .hint_text("unlock code"),
                                );
                                ui.add_space(6.0);
                            }

                            let unlock = ui.add(
                                egui::Button::new(
                                    egui::RichText::new("Unlock Session")
                                        .strong()
                                        .color(egui::Color32::from_rgb(236, 250, 255)),
                                )
                                .fill(egui::Color32::from_rgb(20, 90, 126))
                                .stroke(egui::Stroke::new(
                                    1.0,
                                    egui::Color32::from_rgb(98, 199, 220),
                                ))
                                .min_size(egui::vec2(170.0, 40.0)),
                            );

                            if unlock.clicked() {
                                if let Some(expected) = &self.unlock_required {
                                    if self.form.unlock_code.trim() != expected.trim() {
                                        self.set_feedback("Invalid unlock code", true);
                                        return;
                                    }
                                }
                                self.unlock_ui();
                                self.clear_feedback();
                            }
                        });
                    });
            });
        });
    }

    fn draw_main_ui(&mut self, ctx: &egui::Context) {
        let pulse = ((ctx.input(|i| i.time) as f32) * 0.9).sin() * 0.5 + 0.5;

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(14.0, 9.0);
        style.spacing.window_margin = egui::Margin::same(10.0);
        ctx.set_style(style);

        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(egui::Color32::from_rgb(233, 246, 255));
        visuals.window_fill = egui::Color32::from_rgb(5, 14, 29);
        visuals.panel_fill = egui::Color32::from_rgb(3, 11, 23);
        visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(8, 21, 40);
        visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(28, 70, 118));
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(10, 27, 50);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(17, 47, 84);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(26, 70, 112);
        visuals.selection.bg_fill = egui::Color32::from_rgb(31, 149, 171);
        visuals.extreme_bg_color = egui::Color32::from_rgb(3, 11, 21);
        ctx.set_visuals(visuals);

        let online_count = self
            .runtimes
            .values()
            .filter(|rt| rt.process.is_some())
            .count();
        let active_running = self
            .active_agent
            .as_ref()
            .and_then(|name| self.runtimes.get(name))
            .map(|rt| rt.process.is_some())
            .unwrap_or(false);

        let card_fill = egui::Color32::from_rgba_unmultiplied(7, 20, 40, 228);
        let card_stroke = egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(56, 139, 220, (118.0 + pulse * 60.0) as u8),
        );

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            let top_rect = ui.max_rect();
            let painter = ui.painter_at(top_rect);
            painter.rect_filled(top_rect, 0.0, egui::Color32::from_rgb(4, 13, 27));
            painter.line_segment(
                [top_rect.left_bottom(), top_rect.right_bottom()],
                egui::Stroke::new(1.0, egui::Color32::from_rgb(22, 80, 128)),
            );
            painter.circle_filled(
                top_rect.left_center() + egui::vec2(50.0, 0.0),
                120.0,
                egui::Color32::from_rgba_unmultiplied(38, 118, 226, (20.0 + pulse * 20.0) as u8),
            );
            ui.horizontal(|ui| {
                ui.add_space(2.0);
                ui.vertical(|ui| {
                    ui.heading(
                        egui::RichText::new("Qypha")
                            .size(30.0)
                            .strong()
                            .color(egui::Color32::from_rgb(232, 247, 255)),
                    );
                    ui.label(
                        egui::RichText::new("Native Secure Command Deck")
                            .color(egui::Color32::from_rgb(141, 181, 218)),
                    );
                });
                ui.add_space(20.0);
                ui.label(
                    egui::RichText::new(format!(
                        "{} online / {} total",
                        online_count,
                        self.profiles.len()
                    ))
                    .color(egui::Color32::from_rgb(145, 232, 206))
                    .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Refresh Profiles")
                                    .color(egui::Color32::from_rgb(222, 244, 255))
                                    .strong(),
                            )
                            .fill(egui::Color32::from_rgb(14, 44, 78))
                            .stroke(egui::Stroke::new(
                                1.0,
                                egui::Color32::from_rgb(74, 152, 214),
                            ))
                            .rounding(egui::Rounding::same(999.0)),
                        )
                        .clicked()
                    {
                        self.refresh_profiles();
                        self.sync_form_with_active_profile();
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let rect = ui.max_rect();
            let painter = ui.painter_at(rect);
            painter.rect_filled(rect, 0.0, egui::Color32::from_rgb(3, 9, 19));
            painter.circle_filled(
                rect.left_top() + egui::vec2(120.0, 180.0),
                260.0,
                egui::Color32::from_rgba_unmultiplied(36, 120, 216, (22.0 + pulse * 22.0) as u8),
            );
            painter.circle_filled(
                rect.right_bottom() - egui::vec2(200.0, 120.0),
                280.0,
                egui::Color32::from_rgba_unmultiplied(30, 196, 170, (15.0 + pulse * 20.0) as u8),
            );

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Frame::none()
                    .fill(card_fill)
                    .stroke(card_stroke)
                    .rounding(egui::Rounding::same(16.0))
                    .inner_margin(egui::Margin::symmetric(14.0, 12.0))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                egui::RichText::new("Policy")
                                    .strong()
                                    .color(egui::Color32::from_rgb(186, 226, 255)),
                            );
                            ui.monospace(
                                egui::RichText::new(self.policy_path.display().to_string())
                                    .color(egui::Color32::from_rgb(132, 173, 209)),
                            );
                        });
                    });

                ui.add_space(8.0);

                ui.columns(2, |cols| {
                    let left = &mut cols[0];
                    egui::Frame::none()
                        .fill(card_fill)
                        .stroke(card_stroke)
                        .rounding(egui::Rounding::same(16.0))
                        .inner_margin(egui::Margin::same(14.0))
                        .show(left, |ui| {
                            ui.heading("Runtime + Agent Setup");
                            ui.label(
                                egui::RichText::new(
                                    "launch, mode, transport and security controls",
                                )
                                .color(egui::Color32::from_rgb(135, 175, 210)),
                            );

                            ui.horizontal(|ui| {
                                ui.label("Agent");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.form.agent_name)
                                        .desired_width(220.0)
                                        .hint_text("agent name"),
                                );
                                ui.label("Port");
                                ui.add(
                                    egui::DragValue::new(&mut self.form.listen_port)
                                        .speed(1)
                                        .range(1..=65535),
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label("Transport");
                                egui::ComboBox::from_id_salt("transport")
                                    .selected_text(display_transport_label(&self.form.transport))
                                    .show_ui(ui, |ui| {
                                        for t in ["internet", "tor", "tcp"] {
                                            ui.selectable_value(
                                                &mut self.form.transport,
                                                t.to_string(),
                                                display_transport_label(t),
                                            );
                                        }
                                    });
                                if self.form.transport == "tor" {
                                    ui.label("Mode");
                                    egui::ComboBox::from_id_salt("mode")
                                        .selected_text(self.form.log_mode.clone())
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(
                                                &mut self.form.log_mode,
                                                "safe".to_string(),
                                                "safe",
                                            );
                                            ui.selectable_value(
                                                &mut self.form.log_mode,
                                                "ghost".to_string(),
                                                "ghost",
                                            );
                                        });
                                }
                            });

                            let is_ghost = self.form.log_mode == "ghost";
                            if !is_ghost {
                                ui.horizontal(|ui| {
                                    ui.label("Config");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.form.config_path)
                                            .desired_width(300.0)
                                            .hint_text("/abs/path/qypha_a.toml"),
                                    );
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Passphrase");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.form.passphrase)
                                            .password(true)
                                            .desired_width(300.0),
                                    );
                                });
                            } else {
                                ui.label(
                                    egui::RichText::new(
                                        "Ghost mode: config/passphrase/create-agent disabled",
                                    )
                                    .color(egui::Color32::from_rgb(145, 222, 214)),
                                );
                            }

                            ui.horizontal_wrapped(|ui| {
                                ui.add_enabled_ui(!is_ghost, |ui| {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                egui::RichText::new("Create Agent")
                                                    .color(egui::Color32::from_rgb(228, 245, 255))
                                                    .strong(),
                                            )
                                            .fill(egui::Color32::from_rgb(17, 63, 99))
                                            .stroke(egui::Stroke::new(
                                                1.0,
                                                egui::Color32::from_rgb(79, 170, 218),
                                            ))
                                            .rounding(egui::Rounding::same(999.0)),
                                        )
                                        .clicked()
                                    {
                                        self.create_agent();
                                    }
                                });

                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("Start")
                                                .color(egui::Color32::from_rgb(237, 252, 243))
                                                .strong(),
                                        )
                                        .fill(if active_running {
                                            egui::Color32::from_rgb(26, 64, 46)
                                        } else {
                                            egui::Color32::from_rgb(28, 116, 74)
                                        })
                                        .stroke(egui::Stroke::new(
                                            1.0,
                                            egui::Color32::from_rgb(93, 201, 152),
                                        ))
                                        .rounding(egui::Rounding::same(999.0)),
                                    )
                                    .clicked()
                                {
                                    self.start_runtime();
                                }

                                ui.add_enabled_ui(active_running, |ui| {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                egui::RichText::new("Stop")
                                                    .color(egui::Color32::from_rgb(255, 233, 241))
                                                    .strong(),
                                            )
                                            .fill(egui::Color32::from_rgb(114, 29, 57))
                                            .stroke(egui::Stroke::new(
                                                1.0,
                                                egui::Color32::from_rgb(232, 118, 166),
                                            ))
                                            .rounding(egui::Rounding::same(999.0)),
                                        )
                                        .clicked()
                                    {
                                        self.stop_runtime();
                                    }
                                });
                            });

                            if self.feedback_error {
                                ui.colored_label(
                                    egui::Color32::from_rgb(255, 146, 188),
                                    self.feedback.clone(),
                                );
                            } else {
                                ui.colored_label(
                                    egui::Color32::from_rgb(138, 215, 255),
                                    self.feedback.clone(),
                                );
                            }
                        });

                    let right = &mut cols[1];
                    let mut chosen_agent: Option<String> = None;
                    let runtime_names: Vec<String> = self.runtimes.keys().cloned().collect();
                    for name in runtime_names {
                        if let Some(rt) = self.runtimes.get_mut(&name) {
                            let _ = rt.is_running();
                        }
                    }
                    egui::Frame::none()
                        .fill(card_fill)
                        .stroke(card_stroke)
                        .rounding(egui::Rounding::same(16.0))
                        .inner_margin(egui::Margin::same(14.0))
                        .show(right, |ui| {
                            ui.heading("Local Agents");
                            egui::ScrollArea::vertical()
                                .max_height(260.0)
                                .show(ui, |ui| {
                                    if self.profiles.is_empty() {
                                        ui.label("No agents found");
                                    }
                                    let active_name = self.active_agent.clone();
                                    let profiles: Vec<AgentProfile> =
                                        self.profiles.values().cloned().collect();
                                    for profile in profiles {
                                        let running = self
                                            .runtimes
                                            .get(&profile.name)
                                            .map(|rt| rt.process.is_some())
                                            .unwrap_or(false);
                                        let selected =
                                            active_name.as_deref() == Some(profile.name.as_str());
                                        egui::Frame::none()
                                            .fill(if selected {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    22, 66, 110, 210,
                                                )
                                            } else {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    9, 26, 48, 186,
                                                )
                                            })
                                            .stroke(egui::Stroke::new(
                                                1.0,
                                                if selected {
                                                    egui::Color32::from_rgb(90, 199, 231)
                                                } else {
                                                    egui::Color32::from_rgb(44, 90, 134)
                                                },
                                            ))
                                            .rounding(egui::Rounding::same(12.0))
                                            .inner_margin(egui::Margin::symmetric(10.0, 9.0))
                                            .show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    let online_text =
                                                        if running { "online" } else { "offline" };
                                                    let online_color = if running {
                                                        egui::Color32::from_rgb(110, 228, 177)
                                                    } else {
                                                        egui::Color32::from_rgb(230, 126, 166)
                                                    };
                                                    let row = format!(
                                                        "{} • {} • {} • :{}",
                                                        profile.name,
                                                        profile.mode,
                                                        display_transport_label(&profile.transport),
                                                        profile.listen_port
                                                    );
                                                    if ui.selectable_label(selected, row).clicked()
                                                    {
                                                        chosen_agent = Some(profile.name.clone());
                                                    }
                                                    ui.label(
                                                        egui::RichText::new(online_text)
                                                            .color(online_color)
                                                            .strong(),
                                                    );
                                                });
                                            });
                                        ui.add_space(6.0);
                                    }
                                });
                        });
                    if let Some(agent_name) = chosen_agent {
                        self.active_agent = Some(agent_name);
                        self.sync_form_with_active_profile();
                        self.clear_feedback();
                    }
                });

                ui.add_space(8.0);

                ui.columns(2, |cols| {
                    let (left_slice, right_slice) = cols.split_at_mut(1);
                    let left = &mut left_slice[0];
                    let right = &mut right_slice[0];

                    egui::Frame::none()
                        .fill(card_fill)
                        .stroke(card_stroke)
                        .rounding(egui::Rounding::same(16.0))
                        .inner_margin(egui::Margin::same(14.0))
                        .show(left, |ui| {
                            ui.heading("Invite + Connect");
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("Generate /invite").strong(),
                                        )
                                        .fill(egui::Color32::from_rgb(20, 74, 110))
                                        .rounding(egui::Rounding::same(999.0)),
                                    )
                                    .clicked()
                                {
                                    self.generate_invite(false);
                                }
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.form.group_name)
                                        .hint_text("Group name")
                                        .desired_width(160.0),
                                );
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("Create mailbox group").strong(),
                                        )
                                        .fill(egui::Color32::from_rgb(27, 89, 106))
                                        .rounding(egui::Rounding::same(999.0)),
                                    )
                                    .clicked()
                                {
                                    self.generate_invite(true);
                                }
                            });

                            ui.add_space(4.0);
                            ui.label("Latest invite code");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.latest_invite_code)
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY)
                                    .interactive(false),
                            );
                            if ui.button("Copy invite").clicked() {
                                let invite = self.latest_invite_code.clone();
                                self.copy_text(ctx, &invite, "Invite code");
                            }

                            ui.add_space(4.0);
                            ui.label("Latest mailbox group invite");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.latest_group_invite_code)
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY)
                                    .interactive(false),
                            );
                            if ui.button("Copy mailbox invite").clicked() {
                                let group_invite = self.latest_group_invite_code.clone();
                                self.copy_text(ctx, &group_invite, "Group invite code");
                            }

                            ui.separator();
                            ui.label("Connect invite code");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.form.connect_code)
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY),
                            );
                            if ui.button("Connect").clicked() {
                                self.connect_invite();
                            }
                        });

                    let mode_policy = self.effective_mode_policy();
                    let peers: Vec<PeerRuntime> = self
                        .active_runtime()
                        .map(|rt| rt.peers.values().cloned().collect())
                        .unwrap_or_default();
                    let mut open_dm_action: Option<(String, String)> = None;
                    egui::Frame::none()
                        .fill(card_fill)
                        .stroke(card_stroke)
                        .rounding(egui::Rounding::same(16.0))
                        .inner_margin(egui::Margin::same(14.0))
                        .show(right, |ui| {
                            ui.heading("Peers");
                            if peers.is_empty() {
                                ui.label("No runtime selected");
                            } else {
                                egui::ScrollArea::vertical()
                                    .max_height(350.0)
                                    .show(ui, |ui| {
                                        for peer in peers.clone() {
                                            let did = if mode_policy.mask_did {
                                                mask_did(&peer.did)
                                            } else {
                                                peer.did.clone()
                                            };
                                            egui::Frame::none()
                                                .fill(egui::Color32::from_rgba_unmultiplied(
                                                    10, 30, 56, 190,
                                                ))
                                                .stroke(egui::Stroke::new(
                                                    1.0,
                                                    egui::Color32::from_rgb(45, 100, 152),
                                                ))
                                                .rounding(egui::Rounding::same(12.0))
                                                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                                .show(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.vertical(|ui| {
                                                            ui.label(
                                                                egui::RichText::new(
                                                                    peer.name.clone(),
                                                                )
                                                                .color(egui::Color32::from_rgb(
                                                                    198, 231, 255,
                                                                ))
                                                                .strong(),
                                                            );
                                                            ui.label(did);
                                                            ui.label(
                                                                egui::RichText::new(
                                                                    peer.status.clone(),
                                                                )
                                                                .color(egui::Color32::from_rgb(
                                                                    143, 188, 224,
                                                                )),
                                                            );
                                                        });
                                                        ui.with_layout(
                                                            egui::Layout::right_to_left(
                                                                egui::Align::Center,
                                                            ),
                                                            |ui| {
                                                                if ui.button("Open DM").clicked() {
                                                                    open_dm_action = Some((
                                                                        peer.did.clone(),
                                                                        peer.name.clone(),
                                                                    ));
                                                                }
                                                            },
                                                        );
                                                    });
                                                });
                                            ui.add_space(6.0);
                                        }
                                    });
                            }
                        });
                    if let Some((did, name)) = open_dm_action {
                        self.select_peer_as_dm(&did, &name);
                    }
                });

                ui.add_space(8.0);

                let mode_policy = self.effective_mode_policy();
                let mut mailbox_group_cards: Vec<MailboxGroupSnapshot> = Vec::new();
                let mut mailbox_group_handshake_offers: BTreeMap<
                    String,
                    Vec<PendingGroupHandshakeOffer>,
                > = BTreeMap::new();
                let mut mailbox_security_notes: Vec<String> = Vec::new();
                let mut selected_mailbox_group_id: Option<String> = None;
                let mut mailbox_group_lookup: BTreeMap<String, MailboxGroupSnapshot> =
                    BTreeMap::new();
                let mut action_select_conv: Option<String> = None;
                let mut action_open_group: Option<String> = None;
                let mut action_refresh_group_invite: Option<String> = None;
                let mut action_toggle_menu: Option<String> = None;
                let mut action_close_menu = false;
                let mut action_delete_request: Option<PendingDelete> = None;
                let mut action_transfer_decisions: Vec<(String, String)> = Vec::new();
                let mut action_group_offer_decisions: Vec<(String, String)> = Vec::new();
                let mut action_group_handshake_decisions: Vec<(String, String)> = Vec::new();
                let mut action_kick_group_members: Vec<String> = Vec::new();
                let mut action_send_message = false;
                let mut action_send_transfer = false;
                if let Some(rt) = self.active_runtime() {
                    mailbox_group_lookup = rt.mailbox_groups.clone();
                    mailbox_group_cards = rt.mailbox_groups.values().cloned().collect();
                    mailbox_group_cards.sort_by(|a, b| {
                        mailbox_group_label(a)
                            .cmp(&mailbox_group_label(b))
                            .then_with(|| a.group_id.cmp(&b.group_id))
                    });
                    selected_mailbox_group_id =
                        group_id_from_conversation_key(&rt.active_conversation);
                    for group in &mailbox_group_cards {
                        let offers =
                            pending_group_handshake_offers_for_group(rt, &group.group_id);
                        if !offers.is_empty() {
                            mailbox_group_handshake_offers
                                .insert(group.group_id.clone(), offers);
                        }
                    }
                    mailbox_security_notes.push(
                        "Mailbox groups always use Tor outbound polling and never open peer routes during join."
                            .to_string(),
                    );
                    if rt.transport.eq_ignore_ascii_case("internet") {
                        mailbox_security_notes.push(
                            "Internet transport only affects direct peers. Group plane still stays on Tor mailbox."
                                .to_string(),
                        );
                    }
                    if rt.mode.eq_ignore_ascii_case("ghost") {
                        mailbox_security_notes.push(
                            "Ghost groups are anonymous, RAM-only, and block /invite_h direct trust promotion."
                                .to_string(),
                        );
                    } else {
                        mailbox_security_notes.push(
                            "Safe identified groups expose member IDs, but direct trust still requires explicit /invite_h."
                                .to_string(),
                        );
                    }
                    if mailbox_group_cards.iter().any(|group| group.anonymous_group) {
                        mailbox_security_notes.push(
                            "Anonymous groups never show member DID and can never bridge into a direct peer route."
                                .to_string(),
                        );
                    }
                }

                egui::Frame::none()
                    .fill(card_fill)
                    .stroke(card_stroke)
                    .rounding(egui::Rounding::same(16.0))
                    .inner_margin(egui::Margin::same(14.0))
                    .show(ui, |ui| {
                        ui.heading("Mailbox Groups");
                        if self.active_runtime().is_none() {
                            ui.label("No runtime selected");
                        } else if mailbox_group_cards.is_empty() {
                            ui.label("No mailbox groups joined");
                        } else {
                            egui::ScrollArea::vertical()
                                .max_height(260.0)
                                .show(ui, |ui| {
                                    for group in mailbox_group_cards.clone() {
                                        let selected = selected_mailbox_group_id.as_deref()
                                            == Some(group.group_id.as_str());
                                        let owner_mode = group.local_member_id.is_some()
                                            && group.owner_member_id == group.local_member_id;
                                        let handshake_offers = mailbox_group_handshake_offers
                                            .get(&group.group_id)
                                            .cloned()
                                            .unwrap_or_default();
                                        egui::Frame::none()
                                            .fill(if selected {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    22, 69, 114, 212,
                                                )
                                            } else {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    8, 25, 46, 188,
                                                )
                                            })
                                            .stroke(egui::Stroke::new(
                                                1.0,
                                                if selected {
                                                    egui::Color32::from_rgb(91, 202, 228)
                                                } else {
                                                    egui::Color32::from_rgb(39, 93, 142)
                                                },
                                            ))
                                            .rounding(egui::Rounding::same(12.0))
                                            .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                            .show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    ui.vertical(|ui| {
                                                        ui.label(
                                                            egui::RichText::new(
                                                                mailbox_group_label(&group),
                                                            )
                                                            .color(egui::Color32::from_rgb(
                                                                198, 231, 255,
                                                            ))
                                                            .strong(),
                                                        );
                                                        ui.label(
                                                            egui::RichText::new(
                                                                group.group_id.clone(),
                                                            )
                                                            .small()
                                                            .monospace(),
                                                        );
                                                        ui.label(
                                                            egui::RichText::new(format!(
                                                                "{} • {} • epoch {}",
                                                                if group.anonymous_group {
                                                                    "anonymous"
                                                                } else {
                                                                    "identified"
                                                                },
                                                                group.persistence,
                                                                group.mailbox_epoch
                                                            ))
                                                            .small(),
                                                        );
                                                        if let Some(local_member_id) =
                                                            group.local_member_id.as_ref()
                                                        {
                                                            let member_display =
                                                                if mode_policy.mask_did {
                                                                    mask_did(local_member_id)
                                                                } else {
                                                                    local_member_id.clone()
                                                                };
                                                            ui.label(
                                                                egui::RichText::new(format!(
                                                                    "Local member: {}",
                                                                    member_display
                                                                ))
                                                                .small(),
                                                            );
                                                        }
                                                        if let Some(owner_member_id) =
                                                            group.owner_member_id.as_ref()
                                                        {
                                                            if !group.anonymous_group {
                                                                let owner_display =
                                                                    if mode_policy.mask_did {
                                                                        mask_did(owner_member_id)
                                                                    } else {
                                                                        owner_member_id.clone()
                                                                    };
                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "Owner: {}",
                                                                        owner_display
                                                                    ))
                                                                    .small(),
                                                                );
                                                            }
                                                        }
                                                        ui.label(
                                                            egui::RichText::new(
                                                                mailbox_group_summary(&group),
                                                            )
                                                            .small()
                                                            .color(egui::Color32::from_rgb(
                                                                152, 214, 243,
                                                            )),
                                                        );
                                                        if group.anonymous_group {
                                                            ui.label(
                                                                egui::RichText::new(
                                                                    "Anonymous sandbox group. Traffic stays on Tor mailbox and never opens a direct peer link.",
                                                                )
                                                                .small(),
                                                            );
                                                        } else {
                                                            ui.label(
                                                                egui::RichText::new(
                                                                    "Group traffic stays on Tor mailbox. Use the member ID with /invite_h only for explicit 1:1 trust.",
                                                                )
                                                                .small(),
                                                            );
                                                        }
                                                    });
                                                    ui.with_layout(
                                                        egui::Layout::right_to_left(
                                                            egui::Align::Min,
                                                        ),
                                                        |ui| {
                                                            if ui.button("Refresh Invite").clicked()
                                                            {
                                                                action_refresh_group_invite =
                                                                    Some(group.group_id.clone());
                                                            }
                                                            if ui.button("Open Group").clicked() {
                                                                action_open_group =
                                                                    Some(group.group_id.clone());
                                                            }
                                                        },
                                                    );
                                                });

                                                if !group.known_member_ids.is_empty()
                                                    && !group.anonymous_group
                                                {
                                                    let members = group
                                                        .known_member_ids
                                                        .iter()
                                                        .map(|member_id| {
                                                            if mode_policy.mask_did {
                                                                mask_did(member_id)
                                                            } else {
                                                                member_id.clone()
                                                            }
                                                        })
                                                        .collect::<Vec<_>>()
                                                        .join(", ");
                                                    ui.label(
                                                        egui::RichText::new(format!(
                                                            "Members: {}",
                                                            members
                                                        ))
                                                        .small()
                                                        .weak(),
                                                    );
                                                }

                                                if !handshake_offers.is_empty() {
                                                    ui.add_space(6.0);
                                                    for offer in handshake_offers {
                                                        let sender =
                                                            offer.sender_member_id.clone();
                                                        let sender_display =
                                                            if mode_policy.mask_did {
                                                                mask_did(&sender)
                                                            } else {
                                                                sender
                                                            };
                                                        ui.horizontal_wrapped(|ui| {
                                                            ui.label(
                                                                egui::RichText::new(format!(
                                                                    "Direct trust offer from {}",
                                                                    sender_display
                                                                ))
                                                                .small()
                                                                .color(egui::Color32::from_rgb(
                                                                    184, 224, 252,
                                                                )),
                                                            );
                                                            if ui.button("Accept").clicked() {
                                                                action_group_handshake_decisions
                                                                    .push((
                                                                        "accept".to_string(),
                                                                        offer.sender_member_id
                                                                            .clone(),
                                                                    ));
                                                            }
                                                            if ui.button("Reject").clicked() {
                                                                action_group_handshake_decisions
                                                                    .push((
                                                                        "reject".to_string(),
                                                                        offer.sender_member_id
                                                                            .clone(),
                                                                    ));
                                                            }
                                                            if ui.button("Block").clicked() {
                                                                action_group_handshake_decisions
                                                                    .push((
                                                                        "block".to_string(),
                                                                        offer.sender_member_id
                                                                            .clone(),
                                                                    ));
                                                            }
                                                        });
                                                    }
                                                }

                                                if owner_mode
                                                    && !group.anonymous_group
                                                    && !group.known_member_ids.is_empty()
                                                {
                                                    ui.add_space(6.0);
                                                    ui.horizontal_wrapped(|ui| {
                                                        for member_id in group
                                                            .known_member_ids
                                                            .iter()
                                                            .filter(|member_id| {
                                                                Some(member_id.as_str())
                                                                    != group
                                                                        .local_member_id
                                                                        .as_deref()
                                                            })
                                                        {
                                                            let can_kick =
                                                                can_kick_mailbox_group_member(
                                                                    &mailbox_group_lookup,
                                                                    &group,
                                                                    member_id,
                                                                );
                                                            let label = if mode_policy.mask_did {
                                                                mask_did(member_id)
                                                            } else {
                                                                member_id.clone()
                                                            };
                                                            if ui
                                                                .add_enabled(
                                                                    can_kick,
                                                                    egui::Button::new(format!(
                                                                        "Kick {}",
                                                                        label
                                                                    )),
                                                                )
                                                                .clicked()
                                                            {
                                                                action_kick_group_members
                                                                    .push(member_id.clone());
                                                            }
                                                        }
                                                    });
                                                }
                                            });
                                        ui.add_space(6.0);
                                    }
                                });
                        }

                        if !mailbox_security_notes.is_empty() {
                            ui.separator();
                            for note in mailbox_security_notes.clone() {
                                ui.label(
                                    egui::RichText::new(note)
                                        .small()
                                        .color(egui::Color32::from_rgb(152, 214, 243)),
                                );
                            }
                        }
                    });

                ui.add_space(8.0);

                let mode_policy = self.effective_mode_policy();
                let mut ordered: Vec<Conversation> = Vec::new();
                let mut active_conv: Option<Conversation> = None;
                let mut mailbox_groups: BTreeMap<String, MailboxGroupSnapshot> = BTreeMap::new();
                let mut online_dids: HashSet<String> = HashSet::new();
                let mut pending_for_active: Vec<String> = Vec::new();
                let mut pending_group_offers_for_active: Vec<PendingGroupFileOffer> = Vec::new();
                let mut pending_handshake_offers_for_active: Vec<PendingGroupHandshakeOffer> =
                    Vec::new();
                let mut transfer_lines: Vec<String> = Vec::new();
                let mut transfer_busy = false;
                let mut runtime_name = String::new();

                if let Some(rt) = self.active_runtime() {
                    runtime_name = rt.name.clone();
                    let mut groups: Vec<Conversation> = rt
                        .conversations
                        .values()
                        .filter(|c| c.ctype == ConversationType::Group)
                        .cloned()
                        .collect();
                    groups.sort_by(|a, b| a.title.cmp(&b.title).then_with(|| a.key.cmp(&b.key)));
                    ordered.extend(groups);
                    let mut dms: Vec<Conversation> = rt
                        .conversations
                        .values()
                        .filter(|c| c.ctype == ConversationType::Dm)
                        .cloned()
                        .collect();
                    dms.sort_by(|a, b| a.title.cmp(&b.title));
                    ordered.extend(dms);

                    online_dids = rt.peers.keys().cloned().collect();
                    mailbox_groups = rt.mailbox_groups.clone();
                    active_conv = rt.conversations.get(&rt.active_conversation).cloned();
                    transfer_busy = has_outgoing_transfer(&rt.logs);

                        if let Some(conv) = active_conv.clone() {
                            if let Some(did) = conv.did {
                                pending_for_active = rt
                                    .pending_approvals
                                    .iter()
                                .filter(|v| *v == &did)
                                .cloned()
                                .collect();
                                transfer_lines = transfer_feed_for_active(rt, &did);
                            } else if let Some(group_id) = group_id_from_conversation_key(&conv.key)
                            {
                                pending_group_offers_for_active =
                                    pending_group_file_offers_for_group(rt, &group_id);
                                pending_handshake_offers_for_active =
                                    pending_group_handshake_offers_for_group(rt, &group_id);
                            }
                        }
                    }

                egui::Frame::none()
                    .fill(card_fill)
                    .stroke(card_stroke)
                    .rounding(egui::Rounding::same(16.0))
                    .inner_margin(egui::Margin::same(14.0))
                    .show(ui, |ui| {
                        ui.heading("Conversations");

                        let active_key = self
                            .active_runtime()
                            .map(|rt| rt.active_conversation.clone())
                            .unwrap_or_default();

                        ui.columns(2, |cols| {
                            let (left_slice, right_slice) = cols.split_at_mut(1);
                            let left = &mut left_slice[0];
                            let right = &mut right_slice[0];

                            left.set_min_width(320.0);
                            egui::ScrollArea::vertical()
                                .max_height(350.0)
                                .show(left, |ui| {
                                    for conv in ordered.clone() {
                                        let selected = conv.key == active_key;
                                        let status = if let Some(did) = &conv.did {
                                            if online_dids.contains(did) {
                                                "(online)"
                                            } else {
                                                "(offline)"
                                            }
                                        } else {
                                            ""
                                        };
                                        egui::Frame::none()
                                            .fill(if selected {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    22, 69, 114, 212,
                                                )
                                            } else {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    8, 25, 46, 188,
                                                )
                                            })
                                            .stroke(egui::Stroke::new(
                                                1.0,
                                                if selected {
                                                    egui::Color32::from_rgb(91, 202, 228)
                                                } else {
                                                    egui::Color32::from_rgb(39, 93, 142)
                                                },
                                            ))
                                            .rounding(egui::Rounding::same(12.0))
                                            .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                            .show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    let name = if conv.ctype == ConversationType::Dm
                                                    {
                                                        format!("{} {}", conv.title, status)
                                                    } else {
                                                        conv.title.clone()
                                                    };
                                                    if ui.selectable_label(selected, name).clicked()
                                                    {
                                                        action_select_conv = Some(conv.key.clone());
                                                    }
                                                    if conv.ctype == ConversationType::Dm
                                                        && ui.button("⋯").clicked()
                                                    {
                                                        action_toggle_menu = Some(conv.key.clone());
                                                    }
                                                });

                                                if self.open_menu_key.as_deref()
                                                    == Some(conv.key.as_str())
                                                {
                                                    ui.horizontal(|ui| {
                                                        if ui
                                                            .button("Delete conversation")
                                                            .clicked()
                                                        {
                                                            action_delete_request =
                                                                Some(PendingDelete {
                                                                    agent: runtime_name.clone(),
                                                                    conversation_key: conv
                                                                        .key
                                                                        .clone(),
                                                                    label: conv.title.clone(),
                                                                });
                                                            action_close_menu = true;
                                                        }
                                                        if ui.button("Close").clicked() {
                                                            action_close_menu = true;
                                                        }
                                                    });
                                                }

                                                if let Some(did) = &conv.did {
                                                    let display = if mode_policy.mask_did {
                                                        mask_did(did)
                                                    } else {
                                                        did.clone()
                                                    };
                                                    ui.label(egui::RichText::new(display).small());
                                                } else {
                                                    let group_meta = group_id_from_conversation_key(
                                                        &conv.key,
                                                    )
                                                    .and_then(|group_id| {
                                                        mailbox_groups.get(&group_id)
                                                    })
                                                    .cloned();
                                                    if let Some(group) = group_meta {
                                                        ui.label(
                                                            egui::RichText::new(
                                                                mailbox_group_summary(&group),
                                                            )
                                                            .small(),
                                                        );
                                                        ui.label(
                                                            egui::RichText::new(group.group_id)
                                                                .small()
                                                                .weak(),
                                                        );
                                                    } else {
                                                        ui.label(
                                                            egui::RichText::new(
                                                                "tor mailbox group",
                                                            )
                                                            .small(),
                                                        );
                                                    }
                                                }
                                            });
                                        ui.add_space(6.0);
                                    }
                                });

                            if let Some(conv) = active_conv.clone() {
                                let active_did = conv.did.clone().unwrap_or_default();
                                if conv.ctype == ConversationType::Group {
                                    let group_meta = group_id_from_conversation_key(&conv.key)
                                        .and_then(|group_id| mailbox_groups.get(&group_id))
                                        .cloned();
                                    right.vertical(|ui| {
                                        ui.label(
                                            egui::RichText::new(conv.title.clone())
                                                .color(egui::Color32::from_rgb(177, 213, 241))
                                                .strong(),
                                        );
                                        if let Some(group) = group_meta {
                                            ui.label(
                                                egui::RichText::new(mailbox_group_summary(&group))
                                                    .small()
                                                    .color(egui::Color32::from_rgb(
                                                        152, 214, 243,
                                                    )),
                                            );
                                            ui.label(
                                                egui::RichText::new(group.group_id.clone())
                                                    .small()
                                                    .monospace()
                                                    .color(egui::Color32::from_rgb(
                                                        108, 171, 214,
                                                    )),
                                            );
                                            if group.anonymous_group {
                                                ui.label(
                                                    egui::RichText::new(
                                                        "Anonymous sandbox group. Traffic stays on Tor mailbox and never opens a direct peer link.",
                                                    )
                                                    .small(),
                                                );
                                            } else {
                                                if let Some(local_member_id) =
                                                    group.local_member_id.as_ref()
                                                {
                                                    ui.label(
                                                        egui::RichText::new(format!(
                                                            "Member ID: {}",
                                                            local_member_id
                                                        ))
                                                        .small(),
                                                    );
                                                }
                                                if let Some(owner_member_id) =
                                                    group.owner_member_id.as_ref()
                                                {
                                                    ui.label(
                                                        egui::RichText::new(format!(
                                                            "Owner ID: {}",
                                                            owner_member_id
                                                        ))
                                                        .small(),
                                                    );
                                                }
                                                ui.label(
                                                    egui::RichText::new(
                                                        "Group traffic stays on Tor mailbox. Use the member ID with /invite_h only for explicit 1:1 trust.",
                                                    )
                                                    .small(),
                                                );
                                                if !pending_handshake_offers_for_active.is_empty() {
                                                    ui.add_space(6.0);
                                                    for offer in
                                                        pending_handshake_offers_for_active.clone()
                                                    {
                                                        let sender =
                                                            offer.sender_member_id.clone();
                                                        ui.horizontal_wrapped(|ui| {
                                                            ui.label(
                                                                egui::RichText::new(format!(
                                                                    "Direct trust offer from {}",
                                                                    sender
                                                                ))
                                                                .small()
                                                                .color(egui::Color32::from_rgb(
                                                                    184, 224, 252,
                                                                )),
                                                            );
                                                            if ui.button("Accept").clicked() {
                                                                action_group_handshake_decisions
                                                                    .push((
                                                                        "accept".to_string(),
                                                                        offer.sender_member_id
                                                                            .clone(),
                                                                    ));
                                                            }
                                                            if ui.button("Reject").clicked() {
                                                                action_group_handshake_decisions
                                                                    .push((
                                                                        "reject".to_string(),
                                                                        offer.sender_member_id
                                                                            .clone(),
                                                                    ));
                                                            }
                                                            if ui.button("Block").clicked() {
                                                                action_group_handshake_decisions
                                                                    .push((
                                                                        "block".to_string(),
                                                                        offer.sender_member_id
                                                                            .clone(),
                                                                    ));
                                                            }
                                                        });
                                                    }
                                                }
                                                if !group.known_member_ids.is_empty() {
                                                    ui.add_space(6.0);
                                                    ui.label(
                                                        egui::RichText::new("Members")
                                                            .small()
                                                            .strong(),
                                                    );
                                                    ui.horizontal_wrapped(|ui| {
                                                        for member_id in group
                                                            .known_member_ids
                                                            .iter()
                                                            .filter(|member_id| {
                                                                Some(member_id.as_str())
                                                                    != group
                                                                        .local_member_id
                                                                        .as_deref()
                                                            })
                                                        {
                                                            let can_kick =
                                                                can_kick_mailbox_group_member(
                                                                    &mailbox_groups,
                                                                    &group,
                                                                    member_id,
                                                                );
                                                            let label = if mode_policy.mask_did {
                                                                mask_did(member_id)
                                                            } else {
                                                                member_id.clone()
                                                            };
                                                            if ui
                                                                .add_enabled(
                                                                    can_kick,
                                                                    egui::Button::new(format!(
                                                                        "Kick {}",
                                                                        label
                                                                    )),
                                                                )
                                                                .clicked()
                                                            {
                                                                action_kick_group_members
                                                                    .push(member_id.clone());
                                                            }
                                                        }
                                                    });
                                                }
                                            }
                                        } else {
                                            ui.label(
                                                egui::RichText::new(
                                                    "Tor mailbox sandbox group",
                                                )
                                                .small(),
                                            );
                                        }
                                    });
                                } else {
                                    let did = if mode_policy.mask_did {
                                        mask_did(&active_did)
                                    } else {
                                        active_did.clone()
                                    };
                                    right.label(
                                        egui::RichText::new(format!("{}\n{}", conv.title, did))
                                            .color(egui::Color32::from_rgb(177, 213, 241))
                                            .strong(),
                                    );
                                }

                                egui::ScrollArea::vertical()
                                    .max_height(350.0)
                                    .show(right, |ui| {
                                        if conv.messages.is_empty() {
                                            ui.label("(no messages yet)");
                                        }
                                        for msg in conv.messages {
                                            let align = if msg.direction == MessageDirection::Out {
                                                egui::Align::RIGHT
                                            } else {
                                                egui::Align::LEFT
                                            };
                                            ui.with_layout(
                                                egui::Layout::left_to_right(align),
                                                |ui| {
                                                    let color =
                                                        if msg.direction == MessageDirection::Out {
                                                            egui::Color32::from_rgb(44, 141, 168)
                                                        } else {
                                                            egui::Color32::from_rgb(20, 58, 103)
                                                        };
                                                    egui::Frame::none()
                                                        .fill(color)
                                                        .stroke(egui::Stroke::new(
                                                            1.0,
                                                            egui::Color32::from_rgb(103, 159, 193),
                                                        ))
                                                        .rounding(egui::Rounding::same(12.0))
                                                        .inner_margin(egui::Margin::symmetric(
                                                            10.0, 8.0,
                                                        ))
                                                        .show(ui, |ui| {
                                                            ui.label(
                                                                egui::RichText::new(msg.sender)
                                                                    .strong(),
                                                            );
                                                            ui.label(msg.text);
                                                        });
                                                },
                                            );
                                            ui.add_space(4.0);
                                        }
                                    });
                            } else {
                                right.label("No active conversation");
                            }
                        });

                        if !pending_for_active.is_empty() {
                            ui.separator();
                            for did in pending_for_active.clone() {
                                let display = if mode_policy.mask_did {
                                    mask_did(&did)
                                } else {
                                    did.clone()
                                };
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "Incoming transfer: {}",
                                            display
                                        ))
                                        .color(egui::Color32::from_rgb(184, 224, 252)),
                                    );
                                    if ui.button("Accept").clicked() {
                                        action_transfer_decisions
                                            .push(("accept".to_string(), did.clone()));
                                    }
                                    if ui.button("Reject").clicked() {
                                        action_transfer_decisions
                                            .push(("reject".to_string(), did.clone()));
                                    }
                                    if ui.button("Always").clicked() {
                                        action_transfer_decisions
                                            .push(("always".to_string(), did.clone()));
                                    }
                                    if ui.button("Ask").clicked() {
                                        action_transfer_decisions
                                            .push(("ask".to_string(), did.clone()));
                                    }
                                });
                            }
                        }

                        if !pending_group_offers_for_active.is_empty() {
                            ui.separator();
                            for offer in pending_group_offers_for_active.clone() {
                                let sender = if offer.anonymous_group {
                                    "anonymous member".to_string()
                                } else {
                                    offer
                                        .sender_member_id
                                        .clone()
                                        .unwrap_or_else(|| "unknown member".to_string())
                                };
                                let group_label = offer
                                    .group_name
                                    .clone()
                                    .unwrap_or_else(|| offer.group_id.clone());
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "Incoming group file: {} • {} • {} • {}",
                                            offer
                                                .filename
                                                .clone()
                                                .unwrap_or_else(|| "shared file".to_string()),
                                            sender,
                                            format_byte_count(offer.size_bytes),
                                            group_label
                                        ))
                                        .color(egui::Color32::from_rgb(184, 224, 252)),
                                    );
                                    if ui.button("Accept").clicked() {
                                        action_group_offer_decisions.push((
                                            "accept".to_string(),
                                            offer.manifest_id.clone(),
                                        ));
                                    }
                                    if ui.button("Reject").clicked() {
                                        action_group_offer_decisions.push((
                                            "reject".to_string(),
                                            offer.manifest_id.clone(),
                                        ));
                                    }
                                });
                            }
                        }

                        if !transfer_lines.is_empty() {
                            ui.separator();
                            ui.label(
                                egui::RichText::new("Transfer feed")
                                    .color(egui::Color32::from_rgb(172, 215, 247))
                                    .strong(),
                            );
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgba_unmultiplied(4, 18, 34, 200))
                                .stroke(egui::Stroke::new(
                                    1.0,
                                    egui::Color32::from_rgb(38, 101, 151),
                                ))
                                .rounding(egui::Rounding::same(10.0))
                                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                .show(ui, |ui| {
                                    for line in transfer_lines.clone() {
                                        ui.label(line);
                                    }
                                });
                        }

                        ui.separator();
                        let active_group_id = active_conv
                            .as_ref()
                            .and_then(|conv| group_id_from_conversation_key(&conv.key));
                        let message_hint = if active_group_id.is_some() {
                            "send to selected Tor mailbox group"
                        } else {
                            "type direct message"
                        };
                        ui.horizontal(|ui| {
                            ui.label("Message");
                            let response = ui.add(
                                egui::TextEdit::singleline(&mut self.form.message_input)
                                    .desired_width(500.0)
                                    .hint_text(message_hint),
                            );
                            let enter_pressed = response.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            if ui
                                .add(
                                    egui::Button::new(egui::RichText::new("Send").strong())
                                        .fill(egui::Color32::from_rgb(26, 108, 140))
                                        .rounding(egui::Rounding::same(999.0)),
                                )
                                .clicked()
                                || enter_pressed
                            {
                                action_send_message = true;
                            }
                        });

                        let is_group = active_group_id.is_some();
                        ui.horizontal(|ui| {
                            ui.label("Transfer path");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.form.transfer_path)
                                    .desired_width(500.0)
                                    .hint_text("/absolute/path/file.zip"),
                            );
                            let transfer_label = if is_group {
                                "Transfer to Active Group"
                            } else {
                                "Transfer to Active DM"
                            };
                            ui.add_enabled_ui(!transfer_busy, |ui| {
                                if ui.button(transfer_label).clicked() {
                                    action_send_transfer = true;
                                }
                            });
                            if transfer_busy {
                                ui.label(
                                    egui::RichText::new("Transfer in progress...")
                                        .color(egui::Color32::from_rgb(152, 214, 243)),
                                );
                            }
                        });
                        if is_group {
                            ui.label(
                                egui::RichText::new(
                                    "Group file sharing uses /transfer_g and stays on the Tor mailbox control plane.",
                                )
                                .small()
                                .color(egui::Color32::from_rgb(152, 214, 243)),
                            );
                        }
                    });

                if let Some(key) = action_select_conv {
                    self.select_conversation(&key);
                }
                if let Some(group_id) = action_open_group {
                    self.open_mailbox_group(&group_id);
                }
                if let Some(group_id) = action_refresh_group_invite {
                    self.regenerate_mailbox_group_invite(&group_id);
                }
                if let Some(key) = action_toggle_menu {
                    if self.open_menu_key.as_deref() == Some(key.as_str()) {
                        self.open_menu_key = None;
                    } else {
                        self.open_menu_key = Some(key);
                    }
                }
                if action_close_menu {
                    self.open_menu_key = None;
                }
                if let Some(request) = action_delete_request {
                    self.pending_delete = Some(request);
                }
                for (action, did) in action_transfer_decisions {
                    self.transfer_decision(&action, &did);
                }
                for (action, manifest_id) in action_group_offer_decisions {
                    self.group_file_offer_decision(&action, &manifest_id);
                }
                for (action, sender_member_id) in action_group_handshake_decisions {
                    self.group_handshake_offer_decision(&action, &sender_member_id);
                }
                for member_id in action_kick_group_members {
                    self.kick_group_member(&member_id);
                }
                if action_send_message {
                    self.send_message();
                }
                if action_send_transfer {
                    self.send_transfer();
                }

                ui.add_space(8.0);
                egui::Frame::none()
                    .fill(card_fill)
                    .stroke(card_stroke)
                    .rounding(egui::Rounding::same(16.0))
                    .inner_margin(egui::Margin::same(14.0))
                    .show(ui, |ui| {
                        ui.heading("Runtime Logs");
                        let mode_policy = self.effective_mode_policy();
                        if mode_policy.hide_runtime_logs {
                            ui.label(
                                "Ghost mode: runtime logs hidden in UI (memory-only session). ",
                            );
                        } else if let Some(rt) = self.active_runtime_mut() {
                            let text = rt
                                .logs
                                .iter()
                                .rev()
                                .take(320)
                                .cloned()
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .collect::<Vec<_>>()
                                .join("\n");
                            egui::ScrollArea::vertical()
                                .max_height(230.0)
                                .show(ui, |ui| {
                                    ui.code(text);
                                });
                        } else {
                            ui.label("No runtime selected");
                        }
                    });
            });
        });

        if let Some(pending) = self.pending_delete.clone() {
            egui::Window::new("Delete conversation?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "{} konuşmasını yerel geçmişten silmek istediğine emin misin?",
                        pending.label
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.pending_delete = None;
                        }
                        if ui.button("Delete").clicked() {
                            self.active_agent = Some(pending.agent.clone());
                            self.delete_conversation(&pending.conversation_key);
                            self.pending_delete = None;
                        }
                    });
                });
        }
    }
}

impl eframe::App for QyphaNativeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let user_activity = ctx.input(|i| {
            !i.events.is_empty()
                || i.pointer.any_pressed()
                || i.pointer.any_released()
                || i.pointer.delta() != egui::Vec2::ZERO
        });
        if user_activity {
            self.last_interaction = Instant::now();
        }

        self.process_events();
        self.tick_runtime_health();
        self.enforce_form_transport_constraints();

        if self.ui_locked {
            self.draw_lock_screen(ctx);
            ctx.request_repaint_after(Duration::from_millis(100));
            return;
        }

        self.draw_main_ui(ctx);
        ctx.request_repaint_after(Duration::from_millis(90));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.clear_sensitive_ui_memory();
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Qypha Native")
            .with_inner_size([1460.0, 940.0])
            .with_min_inner_size([1120.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Qypha Native",
        options,
        Box::new(|_cc| Ok(Box::new(QyphaNativeApp::new()))),
    )
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sanitized_agent_name(name: &str) -> String {
    if name.trim().is_empty() {
        "agent".to_string()
    } else {
        name.trim().to_lowercase().replace(' ', "_")
    }
}

fn derived_config_path(root: &Path, name: &str) -> String {
    root.join("agent-configs")
        .join(format!("qypha_{}.toml", sanitized_agent_name(name)))
        .display()
        .to_string()
}

fn resolve_config_path(root: &Path, config: &str) -> PathBuf {
    let p = PathBuf::from(config);
    if p.is_absolute() {
        p
    } else {
        root.join(p)
    }
}

fn build_qypha_command(root: &Path, args: &mut [String]) -> Command {
    if let Ok(explicit) = std::env::var("QYPHA_BIN") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            let mut cmd = Command::new(path);
            for a in args.iter() {
                cmd.arg(a);
            }
            return cmd;
        }
    }
    let bin_name = if cfg!(target_os = "windows") {
        "qypha.exe"
    } else {
        "qypha"
    };
    let debug_bin = root.join("target").join("debug").join(bin_name);
    if debug_bin.exists() {
        let mut cmd = Command::new(debug_bin);
        for a in args.iter() {
            cmd.arg(a);
        }
        return cmd;
    }
    let release_bin = root.join("target").join("release").join(bin_name);
    if release_bin.exists() {
        let mut cmd = Command::new(release_bin);
        for a in args.iter() {
            cmd.arg(a);
        }
        return cmd;
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("run");
    cmd.arg("--manifest-path");
    cmd.arg(root.join("Cargo.toml"));
    cmd.arg("--");
    for a in args.iter() {
        cmd.arg(a);
    }
    cmd
}

fn parse_agent_profile_from_config(path: &Path, fallback_name: &str) -> Option<AgentProfile> {
    let Ok(content) = fs::read_to_string(path) else {
        return None;
    };

    let parsed = toml::from_str::<AgentToml>(&content).ok();
    let agent_name = parsed
        .as_ref()
        .and_then(|p| p.agent.as_ref())
        .and_then(|a| a.name.clone())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| fallback_name.to_string());
    let logging_mode = parsed
        .as_ref()
        .and_then(|p| p.logging.as_ref())
        .and_then(|l| l.mode.clone());
    let security_mode = parsed
        .as_ref()
        .and_then(|p| p.security.as_ref())
        .and_then(|s| s.log_mode.clone());
    let raw_mode = logging_mode.or(security_mode);
    if raw_mode
        .as_deref()
        .is_some_and(|mode| normalize_agent_mode(mode).is_none())
    {
        secure_wipe_file_local(path);
        return None;
    }
    let mode = match raw_mode {
        Some(mode) => normalize_agent_mode(&mode)?,
        None => "safe".to_string(),
    };

    let transport = parsed
        .as_ref()
        .and_then(|p| p.network.as_ref())
        .and_then(|n| n.transport_mode.clone())
        .map(|value| value.to_lowercase());
    if transport
        .as_deref()
        .is_some_and(|value| normalize_agent_transport(value).is_none())
    {
        secure_wipe_file_local(path);
        return None;
    }
    let transport = match transport {
        Some(value) => normalize_agent_transport(&value)?,
        None => "tcp".to_string(),
    };

    let port = parsed
        .as_ref()
        .and_then(|p| p.network.as_ref())
        .and_then(|n| n.listen_port)
        .unwrap_or(9090);

    Some(AgentProfile {
        name: agent_name,
        mode,
        transport,
        listen_port: port,
        config_path: Some(path.display().to_string()),
    })
}

fn normalize_agent_mode(mode: &str) -> Option<String> {
    match mode.trim().to_lowercase().as_str() {
        "ghost" => Some("ghost".to_string()),
        "safe" | "" => Some("safe".to_string()),
        _ => None,
    }
}

fn normalize_agent_transport(transport: &str) -> Option<String> {
    match transport.trim().to_lowercase().as_str() {
        "tcp" | "" => Some("tcp".to_string()),
        "tor" => Some("tor".to_string()),
        "internet" => Some("internet".to_string()),
        _ => None,
    }
}

fn display_transport_label(transport: &str) -> String {
    match transport.trim().to_lowercase().as_str() {
        "tcp" | "lan" => "LAN".to_string(),
        "tor" => "Tor".to_string(),
        "internet" => "Internet".to_string(),
        _ => transport.to_string(),
    }
}

fn normalized_log_mode_for_transport(transport: &str, mode: &str) -> String {
    if transport.trim().eq_ignore_ascii_case("tor") {
        normalize_agent_mode(mode).unwrap_or_else(|| "safe".to_string())
    } else {
        "safe".to_string()
    }
}

fn secure_wipe_file_local(path: &Path) {
    use std::io::{Seek, SeekFrom};

    if !path.exists() {
        return;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        let _ = fs::remove_file(path);
        return;
    }

    let size = metadata.len() as usize;
    if size > 0 {
        if let Ok(mut file) = fs::OpenOptions::new().write(true).open(path) {
            let mut remaining = size;
            let mut buf = vec![0u8; 1024 * 1024];
            while remaining > 0 {
                let chunk = remaining.min(buf.len());
                for byte in &mut buf[..chunk] {
                    *byte = rand::random::<u8>();
                }
                if file.write_all(&buf[..chunk]).is_err() {
                    break;
                }
                remaining -= chunk;
            }
            let _ = file.sync_all();
            let _ = file.seek(SeekFrom::Start(0));
            let _ = file.set_len(0);
            let _ = file.sync_all();
        }
    }

    let _ = fs::remove_file(path);
}

fn discover_agent_profiles(root: &Path) -> Vec<AgentProfile> {
    let mut profiles_by_name = BTreeMap::new();
    let config_root = root.join("agent-configs");

    if let Ok(entries) = fs::read_dir(&config_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if !name.starts_with("qypha_") || !name.ends_with(".toml") {
                continue;
            }

            let fallback_name = name
                .trim_start_matches("qypha_")
                .trim_end_matches(".toml")
                .to_string();

            if let Some(profile) = parse_agent_profile_from_config(&path, &fallback_name) {
                profiles_by_name
                    .entry(profile.name.clone())
                    .or_insert(profile);
            }
        }
    }

    profiles_by_name.into_values().collect()
}

fn spawn_line_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    agent: String,
    tx: Sender<UiEvent>,
) {
    thread::spawn(move || {
        let br = BufReader::new(reader);
        for line in br.lines().map_while(Result::ok) {
            let _ = tx.send(UiEvent::RuntimeLine {
                agent: agent.clone(),
                line,
            });
        }
        let _ = tx.send(UiEvent::RuntimeStreamClosed { agent });
    });
}

fn send_line(rt: &mut AgentRuntime, line: &str, mirror: bool) -> Result<(), String> {
    let clean = validate_command_line(line)?;
    let Some(proc) = rt.process.as_mut() else {
        return Err("Runtime is not running".to_string());
    };
    proc.stdin
        .write_all(clean.as_bytes())
        .map_err(|e| format!("stdin write failed: {}", e))?;
    proc.stdin
        .write_all(b"\n")
        .map_err(|e| format!("stdin write failed: {}", e))?;
    proc.stdin
        .flush()
        .map_err(|e| format!("stdin flush failed: {}", e))?;

    if mirror {
        let mirrored = format!("> {}", clean);
        ingest_runtime_line(rt, mirrored.clone());
        apply_chat_line(rt, &mirrored);
    }

    Ok(())
}

fn encode_ui_bridge_command(command: &UiBridgeCommand) -> Result<String, String> {
    let payload = serde_json::to_vec(command)
        .map_err(|error| format!("Failed to encode UI bridge command: {}", error))?;
    Ok(format!(
        "{}{}",
        UI_BRIDGE_PREFIX,
        URL_SAFE_NO_PAD.encode(payload)
    ))
}

fn validate_command_line(line: &str) -> Result<&str, String> {
    let clean = line.trim();
    if clean.is_empty() {
        return Err("Command is empty".to_string());
    }
    if clean.chars().any(char::is_control) {
        return Err("Command contains forbidden control characters".to_string());
    }
    Ok(clean)
}

fn send_ui_bridge_command(rt: &mut AgentRuntime, command: UiBridgeCommand) -> Result<(), String> {
    let line = encode_ui_bridge_command(&command)?;
    send_line(rt, &line, false)
}

fn push_log(rt: &mut AgentRuntime, line: String) {
    if rt.logs.len() >= 1600 {
        rt.logs.pop_front();
    }
    rt.logs.push_back(line);
}

fn ingest_runtime_line(rt: &mut AgentRuntime, line: String) {
    let normalized = strip_ansi_codes(&line);
    if normalized.trim().is_empty() {
        return;
    }

    if normalized == "MAILBOX_GROUPS_BEGIN" {
        rt.pending_mailbox_groups.clear();
        rt.mailbox_group_refreshing = true;
        return;
    }

    if normalized == "MAILBOX_GROUPS_EMPTY" {
        rt.mailbox_groups.clear();
        rt.pending_mailbox_groups.clear();
        rt.mailbox_group_refreshing = false;
        rt.sync_group_conversations();
        return;
    }

    if normalized == "MAILBOX_GROUPS_END" {
        rt.mailbox_groups = rt
            .pending_mailbox_groups
            .drain(..)
            .map(|group| (group.group_id.clone(), group))
            .collect();
        rt.mailbox_group_refreshing = false;
        rt.sync_group_conversations();
        return;
    }

    if let Some(group) = parse_mailbox_group_json_line(&normalized) {
        if rt.mailbox_group_refreshing {
            rt.pending_mailbox_groups.push(group);
        } else {
            rt.mailbox_groups.insert(group.group_id.clone(), group);
            rt.sync_group_conversations();
        }
        return;
    }

    if let Some(group_event) = parse_group_mailbox_event_json_line(&normalized) {
        apply_group_event_to_runtime(rt, group_event);
        push_log(rt, line);
        return;
    }

    if normalized.contains("connection established") || normalized.contains("Connected to ") {
        if let Some(pid) = extract_peer_id(&normalized) {
            rt.pending_connected_peer_id = Some(pid);
        }
    }

    if let Some((name, pid)) = parse_peers_verbose_header(&normalized) {
        rt.pending_verbose_name = Some(name);
        rt.pending_verbose_peer_id = pid;
        rt.pending_verbose_did = None;
    }

    if normalized.contains("No peers connected.") {
        rt.peers.clear();
        rt.pending_approvals.clear();
        rt.selected_peer = None;
    }

    if normalized.contains("Disconnecting:") || normalized.contains("disconnect requested for") {
        if let Some(did) = extract_did(&normalized) {
            drop_peer(rt, &did);
        }
    }

    if normalized.contains("Peer connected:") {
        if let Some((name, did)) = parse_peer_connected(&normalized) {
            let peer_id = rt.pending_connected_peer_id.take();
            rt.peers.insert(
                did.clone(),
                PeerRuntime {
                    name,
                    did,
                    peer_id,
                    status: "connected".to_string(),
                },
            );
        }
    }

    if normalized.contains("DID:") {
        if let Some(did) = extract_did(&normalized) {
            rt.pending_verbose_did = Some(did.clone());
            let name = rt
                .pending_verbose_name
                .clone()
                .unwrap_or_else(|| did.clone());
            let peer_id = rt.pending_verbose_peer_id.clone();
            rt.peers.insert(
                did.clone(),
                PeerRuntime {
                    name,
                    did,
                    peer_id,
                    status: "ready".to_string(),
                },
            );
        }
    }

    if normalized.contains("Peer ID:") {
        if let (Some(did), Some(peer_id)) =
            (rt.pending_verbose_did.clone(), extract_peer_id(&normalized))
        {
            if let Some(peer) = rt.peers.get_mut(&did) {
                peer.peer_id = Some(peer_id);
            }
        }
    }

    if normalized.contains("Peer disconnected:") {
        if let Some(did) = extract_did(&normalized) {
            drop_peer(rt, &did);
        } else if let Some(peer_id) = extract_peer_id(&normalized) {
            if let Some(did) = find_did_by_peer_id(rt, &peer_id) {
                drop_peer(rt, &did);
            }
        } else if rt.peers.len() <= 1 {
            rt.peers.clear();
            rt.pending_approvals.clear();
            rt.selected_peer = None;
        }
    }

    if normalized.contains("Connection closed peer_id=") {
        if let Some(peer_id) = extract_peer_id(&normalized) {
            if let Some(did) = find_did_by_peer_id(rt, &peer_id) {
                drop_peer(rt, &did);
            }
        }
    }

    if let Some((name, did)) = parse_peers_listing(&normalized) {
        let peer_id = rt.pending_connected_peer_id.clone();
        rt.peers.insert(
            did.clone(),
            PeerRuntime {
                name,
                did,
                peer_id,
                status: "ready".to_string(),
            },
        );
    }

    if normalized.contains("Incoming chunked transfer pending approval:") {
        if let Some(did) = extract_did(&normalized) {
            rt.pending_approvals.insert(did);
        }
    }

    push_log(rt, line);
}

fn drop_peer(rt: &mut AgentRuntime, did: &str) {
    rt.peers.remove(did);
    rt.pending_approvals.remove(did);
    if rt.selected_peer.as_deref() == Some(did) {
        rt.selected_peer = None;
    }
}

fn find_did_by_peer_id(rt: &AgentRuntime, peer_id: &str) -> Option<String> {
    rt.peers
        .values()
        .find(|p| p.peer_id.as_deref() == Some(peer_id))
        .map(|p| p.did.clone())
}

fn parse_peer_connected(line: &str) -> Option<(String, String)> {
    let rest = line.split("Peer connected:").nth(1)?.trim();
    let did = extract_did(rest)?;
    let name = rest.split(" (did:").next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some((name, did))
    }
}

fn parse_peers_verbose_header(line: &str) -> Option<(String, Option<String>)> {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix('[') {
        let close = rest.find(']')?;
        let after = rest[(close + 1)..].trim_start();
        let name = after.split(" — ").next().unwrap_or("").trim().to_string();
        if !name.is_empty() {
            return Some((name, None));
        }
    }
    let dot = t.find(". ")?;
    if !t[..dot].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let after = &t[(dot + 2)..];
    if let Some(open) = after.rfind('[') {
        if after.ends_with(']') && open > 0 {
            let name = after[..open].trim().to_string();
            let peer_id = after[(open + 1)..(after.len() - 1)].trim().to_string();
            if !name.is_empty() {
                return Some((name, (!peer_id.is_empty()).then_some(peer_id)));
            }
        }
    }
    None
}

fn parse_peers_listing(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    let first = trimmed.chars().next()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let rest = trimmed.split_once(". ")?.1;
    let did = extract_did(rest)?;
    let name = rest.split(" (did:").next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some((name, did))
    }
}

fn strip_ansi_codes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn extract_did(text: &str) -> Option<String> {
    let nxf_start = text.find("did:nxf:");
    let qypha_start = text.find("did:qypha:");
    let (start, marker) = match (nxf_start, qypha_start) {
        (Some(nxf), Some(qypha)) => {
            if nxf <= qypha {
                (nxf, "did:nxf:")
            } else {
                (qypha, "did:qypha:")
            }
        }
        (Some(nxf), None) => (nxf, "did:nxf:"),
        (None, Some(qypha)) => (qypha, "did:qypha:"),
        (None, None) => return None,
    };
    let tail = &text[start..];
    let mut end = tail.len();
    for (i, ch) in tail.char_indices() {
        if !(ch.is_ascii_alphanumeric() || ch == ':') {
            end = i;
            break;
        }
    }
    let did = tail[..end].to_string();
    if did.starts_with(marker) {
        Some(did)
    } else {
        None
    }
}

fn extract_peer_id(text: &str) -> Option<String> {
    if let Some(idx) = text.find("peer_id=") {
        let tail = &text[(idx + "peer_id=".len())..];
        let token = tail
            .split(|c: char| c.is_whitespace() || c == ',' || c == ')' || c == ']' || c == '[')
            .next()
            .unwrap_or("")
            .trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    if let Some(idx) = text.find("Peer ID:") {
        let tail = &text[(idx + "Peer ID:".len())..];
        let token = tail
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c: char| c == ')' || c == '(' || c == ',');
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    if let Some(idx) = text.find("Peer disconnected:") {
        let tail = &text[(idx + "Peer disconnected:".len())..].trim();
        let token = tail
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c: char| c == ')' || c == '(' || c == ',');
        if token.starts_with("12D") {
            return Some(token.to_string());
        }
    }
    None
}

fn parse_mailbox_group_json_line(line: &str) -> Option<MailboxGroupSnapshot> {
    let payload = line.strip_prefix("MAILBOX_GROUP ")?;
    serde_json::from_str::<MailboxGroupSnapshot>(payload.trim()).ok()
}

fn parse_group_mailbox_event_json_line(line: &str) -> Option<GroupMailboxRuntimeEvent> {
    let payload = line.strip_prefix("GROUP_MAILBOX_EVENT ")?;
    let mut event = serde_json::from_str::<GroupMailboxRuntimeEvent>(payload.trim()).ok()?;
    if event.ts_ms == 0 {
        event.ts_ms = Utc::now().timestamp_millis();
    }
    Some(event)
}

fn pending_group_file_offers_for_group(
    rt: &AgentRuntime,
    group_id: &str,
) -> Vec<PendingGroupFileOffer> {
    let mut resolved = HashSet::new();
    for event in rt
        .group_events
        .iter()
        .filter(|event| event.group_id == group_id)
    {
        if matches!(
            event.kind.as_str(),
            "file_offer_accepted" | "file_offer_rejected"
        ) {
            if let Some(manifest_id) = event.manifest_id.as_ref() {
                resolved.insert(manifest_id.clone());
            }
        }
    }

    let mut offers = BTreeMap::<String, PendingGroupFileOffer>::new();
    for event in rt
        .group_events
        .iter()
        .filter(|event| event.group_id == group_id)
    {
        if event.kind != "file_offer_pending" {
            continue;
        }
        let Some(manifest_id) = event.manifest_id.as_ref() else {
            continue;
        };
        if resolved.contains(manifest_id) {
            continue;
        }
        offers.insert(
            manifest_id.clone(),
            PendingGroupFileOffer {
                manifest_id: manifest_id.clone(),
                group_id: event.group_id.clone(),
                group_name: event.group_name.clone(),
                anonymous_group: event.anonymous_group,
                sender_member_id: event.sender_member_id.clone(),
                filename: event.filename.clone(),
                size_bytes: event.size_bytes,
            },
        );
    }
    offers.into_values().collect()
}

fn pending_group_handshake_offers_for_group(
    rt: &AgentRuntime,
    group_id: &str,
) -> Vec<PendingGroupHandshakeOffer> {
    let mut offers = BTreeMap::<String, PendingGroupHandshakeOffer>::new();
    for event in rt
        .group_events
        .iter()
        .filter(|event| event.group_id == group_id)
    {
        if event.kind != "direct_handshake_offer" {
            continue;
        }
        let Some(sender_member_id) = event.sender_member_id.as_ref() else {
            continue;
        };
        offers.insert(
            sender_member_id.clone(),
            PendingGroupHandshakeOffer {
                sender_member_id: sender_member_id.clone(),
            },
        );
    }
    offers.into_values().collect()
}

fn can_kick_mailbox_group_member(
    groups: &BTreeMap<String, MailboxGroupSnapshot>,
    group: &MailboxGroupSnapshot,
    member_id: &str,
) -> bool {
    if group.anonymous_group {
        return false;
    }
    let Some(local_member_id) = group.local_member_id.as_ref() else {
        return false;
    };
    if group.owner_member_id.as_deref() != Some(local_member_id.as_str()) {
        return false;
    }
    if member_id.is_empty() || member_id == local_member_id {
        return false;
    }
    let owner_controlled_matches = groups
        .values()
        .filter(|candidate| {
            !candidate.anonymous_group
                && candidate.local_member_id.is_some()
                && candidate.owner_member_id == candidate.local_member_id
                && candidate
                    .known_member_ids
                    .iter()
                    .any(|known| known == member_id)
        })
        .count();
    owner_controlled_matches == 1
}

fn format_byte_count(bytes: Option<u64>) -> String {
    let Some(bytes) = bytes else {
        return "size unknown".to_string();
    };
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    if bytes < 1024 * 1024 * 1024 {
        return format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0));
    }
    format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

fn clear_direct_handshake_offer_events(
    rt: &mut AgentRuntime,
    sender_member_id: Option<&str>,
    invite_code: Option<&str>,
) {
    rt.group_events.retain(|event| {
        if event.kind != "direct_handshake_offer" {
            return true;
        }
        let sender_matches = sender_member_id
            .map(|sender| event.sender_member_id.as_deref() == Some(sender))
            .unwrap_or(false);
        let invite_matches = invite_code
            .map(|invite| event.invite_code.as_deref() == Some(invite))
            .unwrap_or(false);
        !(sender_matches || invite_matches)
    });
}

fn apply_group_event_to_runtime(rt: &mut AgentRuntime, event: GroupMailboxRuntimeEvent) {
    if matches!(
        event.kind.as_str(),
        "direct_handshake_offer_accepted"
            | "direct_handshake_offer_rejected"
            | "direct_handshake_offer_blocked"
    ) {
        clear_direct_handshake_offer_events(
            rt,
            event.sender_member_id.as_deref(),
            event.invite_code.as_deref(),
        );
    }
    if rt.group_events.len() >= 400 {
        rt.group_events.pop_front();
    }
    rt.group_events.push_back(event.clone());

    let group = rt
        .mailbox_groups
        .entry(event.group_id.clone())
        .or_insert_with(|| MailboxGroupSnapshot {
            group_id: event.group_id.clone(),
            group_name: event.group_name.clone(),
            anonymous_group: event.anonymous_group,
            anonymous_security_state: None,
            persistence: "memory_only".to_string(),
            local_member_id: None,
            owner_member_id: None,
            owner_special_id: None,
            known_member_ids: Vec::new(),
            mailbox_epoch: event.mailbox_epoch.unwrap_or_default(),
        });
    if event
        .group_name
        .as_ref()
        .is_some_and(|name| !name.trim().is_empty())
    {
        group.group_name = event.group_name.clone();
    }
    group.anonymous_group = event.anonymous_group;
    if let Some(epoch) = event.mailbox_epoch {
        group.mailbox_epoch = epoch;
    }
    if let Some(member_id) = event.member_id.as_ref() {
        if !group
            .known_member_ids
            .iter()
            .any(|candidate| candidate == member_id)
        {
            group.known_member_ids.push(member_id.clone());
            group.known_member_ids.sort();
        }
    }
    if let Some(kicked_member_id) = event.kicked_member_id.as_ref() {
        group
            .known_member_ids
            .retain(|member_id| member_id != kicked_member_id);
    }

    let title = mailbox_group_label(group);
    let key = rt.ensure_group_conversation(&event.group_id, &title);
    let message = match event.kind.as_str() {
        "chat" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: event
                .sender_member_id
                .clone()
                .unwrap_or_else(|| "anonymous member".to_string()),
            text: event.message.clone().unwrap_or_default(),
        }),
        "file_manifest" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: format!(
                "shared file{}",
                event
                    .filename
                    .as_ref()
                    .map(|filename| format!(" • {}", filename))
                    .unwrap_or_default()
            ),
        }),
        "file_offer_pending" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: event.message.clone().unwrap_or_else(|| {
                format!(
                    "approval required{}",
                    event
                        .filename
                        .as_ref()
                        .map(|filename| format!(" • {}", filename))
                        .unwrap_or_default()
                )
            }),
        }),
        "file_offer_accepted" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: event.message.clone().unwrap_or_else(|| {
                format!(
                    "accepted{}",
                    event
                        .filename
                        .as_ref()
                        .map(|filename| format!(" • {}", filename))
                        .unwrap_or_default()
                )
            }),
        }),
        "file_offer_rejected" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: event.message.clone().unwrap_or_else(|| {
                format!(
                    "rejected{}",
                    event
                        .filename
                        .as_ref()
                        .map(|filename| format!(" • {}", filename))
                        .unwrap_or_default()
                )
            }),
        }),
        "membership_notice" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: format!(
                "member joined • {}",
                event
                    .member_display_name
                    .clone()
                    .or_else(|| event.member_id.clone())
                    .unwrap_or_else(|| "unknown member".to_string())
            ),
        }),
        "direct_handshake_offer" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: format!(
                "direct trust offer from {}",
                event
                    .sender_member_id
                    .clone()
                    .unwrap_or_else(|| "unknown member".to_string())
            ),
        }),
        "direct_handshake_offer_accepted" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: event.message.clone().unwrap_or_else(|| {
                format!(
                    "direct trust accepted • {}",
                    event
                        .sender_member_id
                        .clone()
                        .unwrap_or_else(|| "unknown member".to_string())
                )
            }),
        }),
        "direct_handshake_offer_rejected" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: event.message.clone().unwrap_or_else(|| {
                format!(
                    "direct trust rejected • {}",
                    event
                        .sender_member_id
                        .clone()
                        .unwrap_or_else(|| "unknown member".to_string())
                )
            }),
        }),
        "direct_handshake_offer_blocked" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: event.message.clone().unwrap_or_else(|| {
                format!(
                    "direct trust blocked • {}",
                    event
                        .sender_member_id
                        .clone()
                        .unwrap_or_else(|| "unknown member".to_string())
                )
            }),
        }),
        "mailbox_rotation" | "local_kick" => Some(ChatMessage {
            direction: MessageDirection::In,
            sender: "system".to_string(),
            text: format!(
                "mailbox epoch {} • removed {}",
                event.mailbox_epoch.unwrap_or_default(),
                event
                    .kicked_member_id
                    .clone()
                    .unwrap_or_else(|| "member".to_string())
            ),
        }),
        _ => None,
    };

    if let Some(message) = message {
        rt.append_message(&key, message);
    }
    rt.sync_group_conversations();
}

fn parse_incoming_chat(line: &str) -> Option<(String, String)> {
    let normalized = strip_ansi_codes(line);
    let marker = "[sig verified][E2EE]";
    let start = normalized.find(marker)?;
    let tail = normalized[(start + marker.len())..].trim();
    let idx = tail.find(':')?;
    let sender = tail[..idx].trim().to_string();
    let message = tail[(idx + 1)..].trim().to_string();
    if sender.is_empty() {
        None
    } else {
        Some((sender, message))
    }
}

fn parse_outgoing_command(line: &str) -> Option<OutgoingCommand> {
    if !line.starts_with("> ") {
        return None;
    }
    let cmd = line[2..].trim();
    if let Some(rest) = cmd.strip_prefix("/sendto ") {
        let first_space = rest.find(' ')?;
        if first_space < 1 {
            return None;
        }
        let peer = rest[..first_space].trim().to_string();
        let message = rest[(first_space + 1)..].trim().to_string();
        if message.is_empty() {
            return None;
        }
        if looks_like_group_id(&peer) {
            return Some(OutgoingCommand::Group {
                group_id: peer,
                message,
            });
        }
        return Some(OutgoingCommand::Dm { peer, message });
    }
    None
}

enum OutgoingCommand {
    Group { group_id: String, message: String },
    Dm { peer: String, message: String },
}

fn apply_chat_line(rt: &mut AgentRuntime, line: &str) {
    if let Some((sender, message)) = parse_incoming_chat(line) {
        if let Some(did) = resolve_sender_did(rt, &sender) {
            if rt.deleted_dids.contains(&did) {
                rt.deleted_dids.remove(&did);
            }
            rt.sender_did_cache
                .insert(sender.to_lowercase(), did.clone());
            let sender_name = display_name_for_did(rt, &did, Some(&sender));
            let key = rt.ensure_dm_conversation(&did, &sender_name);
            rt.append_message(
                &key,
                ChatMessage {
                    direction: MessageDirection::In,
                    sender: sender_name,
                    text: message,
                },
            );
        } else {
            let key = format!("dm:unresolved:{}", sender.to_lowercase());
            if !rt.conversations.contains_key(&key) {
                rt.conversations.insert(
                    key.clone(),
                    Conversation {
                        key: key.clone(),
                        ctype: ConversationType::Dm,
                        title: sender.clone(),
                        did: None,
                        messages: Vec::new(),
                    },
                );
            }
            rt.append_message(
                &key,
                ChatMessage {
                    direction: MessageDirection::In,
                    sender,
                    text: message,
                },
            );
        }
        return;
    }

    if let Some(outgoing) = parse_outgoing_command(line) {
        match outgoing {
            OutgoingCommand::Group { group_id, message } => {
                let title = rt
                    .mailbox_groups
                    .get(&group_id)
                    .map(mailbox_group_label)
                    .unwrap_or_else(|| group_id.clone());
                let key = rt.ensure_group_conversation(&group_id, &title);
                rt.append_message(
                    &key,
                    ChatMessage {
                        direction: MessageDirection::Out,
                        sender: "you".to_string(),
                        text: message,
                    },
                );
            }
            OutgoingCommand::Dm { peer, message } => {
                let did = if peer.starts_with("did:nxf:") || peer.starts_with("did:qypha:") {
                    Some(peer.clone())
                } else {
                    find_did_by_name(rt, &peer)
                };
                if let Some(did) = did {
                    if rt.deleted_dids.contains(&did) {
                        return;
                    }
                    let title = display_name_for_did(rt, &did, Some(&peer));
                    let key = rt.ensure_dm_conversation(&did, &title);
                    rt.append_message(
                        &key,
                        ChatMessage {
                            direction: MessageDirection::Out,
                            sender: "you".to_string(),
                            text: message,
                        },
                    );
                }
            }
        }
    }
}

fn resolve_sender_did(rt: &AgentRuntime, sender: &str) -> Option<String> {
    if sender.starts_with("did:nxf:") || sender.starts_with("did:qypha:") {
        return Some(sender.to_string());
    }
    if let Some(by_name) = find_did_by_name(rt, sender) {
        return Some(by_name);
    }
    let matches: Vec<String> = rt
        .conversations
        .values()
        .filter_map(|c| {
            if c.ctype == ConversationType::Dm
                && c.title.eq_ignore_ascii_case(sender)
                && c.did.is_some()
            {
                c.did.clone()
            } else {
                None
            }
        })
        .collect();
    if matches.len() == 1 {
        return Some(matches[0].clone());
    }
    if let Some(cached) = rt.sender_did_cache.get(&sender.to_lowercase()) {
        return Some(cached.clone());
    }
    if rt.peers.len() == 1 {
        return rt.peers.values().next().map(|p| p.did.clone());
    }
    None
}

fn find_did_by_name(rt: &AgentRuntime, name: &str) -> Option<String> {
    let matches: Vec<String> = rt
        .peers
        .values()
        .filter(|p| p.name.eq_ignore_ascii_case(name))
        .map(|p| p.did.clone())
        .collect();
    if matches.len() == 1 {
        Some(matches[0].clone())
    } else {
        None
    }
}

fn display_name_for_did(rt: &AgentRuntime, did: &str, fallback: Option<&str>) -> String {
    if let Some(peer) = rt.peers.get(did) {
        if !peer.name.trim().is_empty() {
            return peer.name.clone();
        }
    }
    if let Some(fb) = fallback {
        if !fb.starts_with("did:nxf:") && !fb.starts_with("did:qypha:") {
            return fb.to_string();
        }
    }
    did.to_string()
}

fn refresh_invite_codes(rt: &AgentRuntime, direct_out: &mut String, group_out: &mut String) {
    let mut direct: Option<String> = None;
    let mut group: Option<String> = None;
    let lines: Vec<String> = rt
        .logs
        .iter()
        .map(|v| strip_ansi_codes(v).trim().to_string())
        .collect();

    for i in 0..lines.len() {
        let line = lines[i].as_str();

        if line.contains("═══ Invite Code ═══") {
            for line2 in lines.iter().skip(i + 1) {
                if looks_like_invite_code(line2) {
                    direct = Some(line2.clone());
                    break;
                }
            }
        }

        if line.contains("═══ Group Invite Code ═══")
            || line.contains("═══ Group Invite ═══")
            || line.contains("═══ Ghost Group Invite ═══")
            || line.contains("═══ Anonymous Group Invite ═══")
        {
            for line2 in lines.iter().skip(i + 1) {
                if looks_like_invite_code(line2) {
                    group = Some(line2.clone());
                    break;
                }
            }
        }

        if line.contains("Share this code with the peer you want to connect to.") {
            let prev = if i > 0 { lines[i - 1].as_str() } else { "" };
            if looks_like_invite_code(prev) {
                direct = Some(prev.to_string());
            }
        }

        if line.contains("Reusable invite: multiple peers can join this group.") {
            let prev = if i > 0 { lines[i - 1].as_str() } else { "" };
            if looks_like_invite_code(prev) {
                group = Some(prev.to_string());
            }
        }
    }

    *direct_out = direct.unwrap_or_default();
    *group_out = group.unwrap_or_default();
}

fn looks_like_invite_code(text: &str) -> bool {
    let t = text.trim();
    !t.is_empty()
        && t.len() >= 80
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn normalize_invite_code(raw: &str) -> String {
    if let Some(token) = raw
        .split(|c: char| c.is_whitespace())
        .find(|t| looks_like_invite_code(t))
    {
        return token.trim().to_string();
    }
    raw.split_whitespace().collect::<String>()
}

fn mask_did(did: &str) -> String {
    if !(did.starts_with("did:nxf:") || did.starts_with("did:qypha:")) || did.len() < 22 {
        return did.to_string();
    }
    let head = &did[..20.min(did.len())];
    let tail = &did[did.len().saturating_sub(8)..];
    format!("{}…{}", head, tail)
}

fn has_active_transfer(logs: &VecDeque<String>) -> bool {
    let mut start_idx: i64 = -1;
    let mut end_idx: i64 = -1;
    for (i, raw) in logs.iter().enumerate() {
        let line = strip_ansi_codes(raw);
        if line.contains("Init sent: session ")
            || line.contains("Pending: waiting for receiver /accept before sending chunks")
            || line.contains("Sending: [")
            || line.contains("Busy: another transfer is already in progress")
            || line.contains("Incoming chunked transfer pending approval:")
            || line.contains("Chunked transfer from:")
            || line.contains("Receiving: [")
        {
            start_idx = i as i64;
        }
        if line.contains("Sent: ")
            || line.contains("Transfer REJECTED:")
            || line.contains("Transfer rejected")
            || line.contains("Chunked transfer reassembly FAILED")
            || line.contains("Chunked transfer complete:")
            || line.contains("Peer disconnected:")
            || line.contains("Disconnecting:")
            || line.contains("No peers connected.")
        {
            end_idx = i as i64;
        }
    }
    start_idx > end_idx
}

fn has_outgoing_transfer(logs: &VecDeque<String>) -> bool {
    let mut start_idx: i64 = -1;
    let mut end_idx: i64 = -1;
    for (i, raw) in logs.iter().enumerate() {
        let line = strip_ansi_codes(raw);
        if line.contains("Init sent: session ")
            || line.contains("Pending: waiting for receiver /accept before sending chunks")
            || line.contains("Transfer start approved by receiver")
            || line.contains("Start: ")
            || line.contains("Sending: [")
        {
            start_idx = i as i64;
        }
        if line.contains("Sent: ")
            || line.contains("Transfer REJECTED:")
            || line.contains("Transfer rejected")
        {
            end_idx = i as i64;
        }
    }
    start_idx > end_idx
}

fn transfer_feed_for_active(rt: &AgentRuntime, did: &str) -> Vec<String> {
    let mut feed = Vec::new();
    for raw in rt.logs.iter().rev() {
        let line = strip_ansi_codes(raw);
        if line.contains(did)
            || line.contains("Receiving: [")
            || line.contains("Sending: [")
            || line.contains("Pending: waiting for receiver /accept")
            || line.contains("Transfer start approved by receiver")
            || line.contains("Transfer REJECTED:")
            || line.contains("Chunked transfer complete:")
            || line.contains("Chunked transfer reassembly FAILED")
        {
            feed.push(strip_runtime_prefix(&line));
            if feed.len() >= 7 {
                break;
            }
        }
    }
    feed.reverse();
    feed
}

fn strip_runtime_prefix(line: &str) -> String {
    let mut out = line.to_string();
    if let Some(idx) = out.find("> ") {
        if idx < 24
            && out[..idx].chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == '['
                    || c == ']'
                    || c == ' '
                    || c == '_'
                    || c == '-'
            })
        {
            out = out[(idx + 2)..].to_string();
        }
    }
    if out.starts_with("[stderr] ") {
        out = out[9..].to_string();
    }
    out.trim().to_string()
}

fn best_effort_clear_clipboard() {
    if cfg!(target_os = "macos") {
        let _ = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(b"");
                }
                child.wait()
            });
    } else if cfg!(target_os = "linux") {
        let _ = Command::new("sh")
            .arg("-lc")
            .arg("printf '' | xclip -selection clipboard")
            .status();
        let _ = Command::new("sh")
            .arg("-lc")
            .arg("printf '' | wl-copy")
            .status();
    } else if cfg!(target_os = "windows") {
        let _ = Command::new("cmd").args(["/C", "echo off | clip"]).status();
    }
}

fn best_effort_copy_to_os_clipboard(text: &str) {
    if cfg!(target_os = "macos") {
        let _ = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                child.wait()
            });
    }
}

fn looks_like_screenshot_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
        return false;
    };
    let n = name.to_lowercase();
    n.contains("screen shot") || n.contains("screenshot") || n.contains("ekran görüntüsü")
}
