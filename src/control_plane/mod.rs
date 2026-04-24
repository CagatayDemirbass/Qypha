pub mod audit;
pub mod log_policy;
/// Control Plane — centralized management for the agent network
///
/// Components:
/// - Policy Engine: RBAC-backed permission evaluation
/// - Audit Ledger: Encrypted, chain-hashed audit trail
/// - RBAC Engine: Role-based access control with flexible role definitions
/// - Log Policy Manager: Per-agent log mode management
pub mod policy;
pub mod rbac;
