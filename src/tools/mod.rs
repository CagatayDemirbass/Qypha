/// Tools — agent capabilities (inspired by IronClaw's WASM tool system)
///
/// Built-in tools:
/// - Shell: execute commands
/// - FileSystem: read/write/list
/// - Browser: CDP-based browser control
/// - HTTP: make API calls
///
/// WASM tools (sandboxed):
/// - Custom tools loaded at runtime
/// - Capability-based permissions
/// - Credential injection at host boundary

pub struct ToolRegistry;
