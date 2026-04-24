use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::runtime::contracts::{ProviderKind, RuntimeAccessMode};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedCapability {
    Provider,
    Research,
    Browser,
    Document,
    Memory,
    Os,
    Repo,
    PluginMcp,
}

#[derive(Debug, Clone)]
pub struct EmbeddedVendorSpec {
    pub capability: EmbeddedCapability,
    pub notes: &'static str,
    pub upstream_paths: &'static [&'static str],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedWorkerProfile {
    pub agent_name: String,
    pub provider: ProviderKind,
    #[serde(default)]
    pub model_id: Option<String>,
    pub access_mode: RuntimeAccessMode,
    pub safe_mode_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedBridgeConfig {
    pub snapshot_root: PathBuf,
    pub vendored_root: PathBuf,
    pub node_entrypoint: PathBuf,
    pub worker_supervisor_dir: PathBuf,
}

impl EmbeddedBridgeConfig {
    pub fn for_workspace_root(workspace_root: &Path) -> Self {
        let snapshot_root = workspace_root
            .join("vendor")
            .join("openclaw_snapshot")
            .join("upstream")
            .join("openclaw");
        let vendored_root = workspace_root.join("embedded_runtime");
        let node_entrypoint = vendored_root.join("bridge").join("worker-entry.ts");
        let worker_supervisor_dir = workspace_root
            .join("agent-configs")
            .join("embedded-workers");
        Self {
            snapshot_root,
            vendored_root,
            node_entrypoint,
            worker_supervisor_dir,
        }
    }

    pub fn resolve_upstream_path(&self, relative_path: &str) -> PathBuf {
        self.snapshot_root.join(relative_path)
    }

    pub fn resolve_vendored_path(&self, relative_path: &str) -> PathBuf {
        self.vendored_root.join(relative_path)
    }
}

pub const EMBEDDED_VENDOR_SPECS: &[EmbeddedVendorSpec] = &[
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::Provider,
        notes: "Qypha AI agent provider catalog and model runtime will be vendored directly from OpenClaw; Qypha keeps actor/session/policy ownership.",
        upstream_paths: &[
            "src/plugins/types.ts",
            "src/plugins/providers.ts",
            "src/plugins/loader.ts",
            "src/plugins/manifest-registry.ts",
            "src/plugins/provider-catalog.ts",
            "src/plugins/provider-catalog-metadata.ts",
            "src/plugins/provider-runtime.ts",
            "src/plugins/provider-runtime.runtime.ts",
            "src/plugins/provider-discovery.ts",
            "src/plugins/provider-validation.ts",
            "src/plugins/provider-api-key-auth.ts",
            "src/plugins/provider-ollama-setup.ts",
            "src/plugin-sdk/provider-entry.ts",
            "src/plugin-sdk/plugin-entry.ts",
            "src/plugin-sdk/provider-models.ts",
            "src/plugin-sdk/provider-stream.ts",
            "src/plugin-sdk/provider-auth.ts",
            "src/plugin-sdk/provider-catalog.ts",
            "src/plugin-sdk/ollama-setup.ts",
            "extensions/ollama/index.ts",
            "extensions/openai/index.ts",
            "extensions/anthropic/index.ts",
            "extensions/google/index.ts",
        ],
    },
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::Research,
        notes: "Research runtime must behave like OpenClaw: search, inspect best sources, synthesize with uncertainty and citations.",
        upstream_paths: &[
            "src/web-search/runtime.ts",
            "src/plugins/web-search-providers.shared.ts",
            "src/plugins/web-search-providers.runtime.ts",
            "src/plugins/bundled-web-search-provider-ids.ts",
            "src/bundled-web-search-registry.ts",
            "extensions/duckduckgo/index.ts",
            "extensions/brave/index.ts",
            "extensions/exa/index.ts",
            "extensions/tavily/index.ts",
            "extensions/firecrawl/index.ts",
            "extensions/google/src/gemini-web-search-provider.ts",
        ],
    },
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::Browser,
        notes: "Browser runtime stays OpenClaw-native; Qypha only wraps it with session identity, approvals, and policy gates.",
        upstream_paths: &[
            "src/browser/client.ts",
            "src/browser/client-actions.ts",
            "src/browser/pw-session.ts",
            "src/browser/pw-tools-core.ts",
            "src/browser/profiles.ts",
            "src/browser/profile-capabilities.ts",
            "src/browser/request-policy.ts",
            "src/browser/navigation-guard.ts",
            "src/browser/session-tab-registry.ts",
            "src/node-host/invoke-browser.ts",
            "src/plugins/setup-browser.ts",
        ],
    },
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::Document,
        notes: "PDF and document understanding will stay on OpenClaw extraction code; Qypha only normalizes the results into its own runtime contract.",
        upstream_paths: &[
            "src/media/pdf-extract.ts",
            "src/media/file-context.ts",
            "src/media/input-files.ts",
            "extensions/openai/media-understanding-provider.ts",
            "extensions/anthropic/media-understanding-provider.ts",
            "extensions/google/media-understanding-provider.ts",
        ],
    },
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::Memory,
        notes: "Memory stays source-linked and actor-scoped. Durable AI memory is safe-mode only.",
        upstream_paths: &[
            "src/plugin-sdk/memory-core.ts",
            "src/plugin-sdk/memory-lancedb.ts",
            "extensions/memory-core/index.ts",
            "extensions/memory-lancedb/index.ts",
            "extensions/memory-lancedb/lancedb-runtime.ts",
            "extensions/memory-lancedb/api.ts",
            "src/hooks/bundled/session-memory/handler.ts",
        ],
    },
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::Os,
        notes: "Full OS control comes from OpenClaw openshell runtime, but Qypha keeps the approval boundary and maps it to typed operations.",
        upstream_paths: &[
            "extensions/openshell/index.ts",
            "extensions/openshell/src/backend.ts",
            "extensions/openshell/src/cli.ts",
            "extensions/openshell/src/config.ts",
            "extensions/openshell/src/fs-bridge.ts",
            "extensions/openshell/src/remote-fs-bridge.ts",
            "extensions/openshell/src/mirror.ts",
        ],
    },
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::Repo,
        notes: "Repo/runtime inspection should stay OpenClaw-native where possible; Qypha maps it into actor/session scoped typed repo operations.",
        upstream_paths: &[
            "src/agents/pi-tools.ts",
            "src/agents/pi-tools.read.ts",
            "src/agents/apply-patch.ts",
            "src/agents/bash-tools.ts",
            "src/agents/bash-tools.exec-runtime.ts",
        ],
    },
    EmbeddedVendorSpec {
        capability: EmbeddedCapability::PluginMcp,
        notes: "Plugin and MCP capability loading stays OpenClaw-native, but Qypha owns registry visibility, policy, approvals, and invocation envelopes.",
        upstream_paths: &[
            "src/plugins/runtime/index.ts",
            "src/plugins/runtime/types-core.ts",
            "src/plugins/loader.ts",
            "src/plugins/manifest-registry.ts",
            "src/plugins/bundle-mcp.ts",
            "src/plugin-sdk/plugin-runtime.ts",
            "src/agents/pi-bundle-mcp-tools.ts",
            "src/agents/embedded-pi-mcp.ts",
        ],
    },
];

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn default_embedded_bridge_config() -> EmbeddedBridgeConfig {
    EmbeddedBridgeConfig::for_workspace_root(&workspace_root())
}
