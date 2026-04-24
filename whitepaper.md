# Qypha Security and Privacy Whitepaper

Last reviewed: April 19, 2026

## 1. Scope and Method

This document describes the security, privacy, persistence, discovery, messaging, and file-transfer behavior implemented in the current Qypha codebase. It is intentionally written as an implementation-backed engineering report rather than a marketing overview.

The guiding rules for this whitepaper are:

- If the current branch clearly implements a security property, the report says so directly.
- If the current branch only provides a best-effort hardening or cleanup measure, the report says so directly.
- If a feature exists but still carries metadata, persistence, or deployment caveats, those caveats are disclosed explicitly.
- If multiple identity layers or protocol layers exist, the distinction is made clear instead of flattened into a simpler but inaccurate story.

The report covers:

- agent identity, DID design, and key material
- DID-first discovery and contact establishment
- direct invite and group invite behavior
- handshake authentication and message admission
- direct 1:1 messaging and Double Ratchet behavior
- file transfer, chunked transfer, relay paths, and artifact packaging
- Safe mode and Ghost mode
- at-rest encryption and audit design
- runtime cleanup, terminal cleanup, and anti-forensic behavior
- embedded AI runtime caveats

## 2. Executive Summary

Qypha is a privacy-first, decentralized agent communication system built around four security layers at once:

1. signed identity and authenticated request admission
2. application-layer end-to-end encryption for direct chat and file transfer
3. mailbox, bundle, and capability-based discovery/onboarding paths
4. Safe and Ghost runtime modes that shape persistence and cleanup behavior

The current codebase uses the following core primitives:

- Ed25519 for identity and signatures
- X25519 for classical ECDH
- Kyber-1024 for post-quantum KEM material
- AEGIS-256 as the primary AEAD for current ratchet and artifact paths
- XChaCha20-Poly1305 as the outer cascade AEAD in hybrid envelopes
- AES-256-GCM for at-rest state and compatibility paths
- HKDF-SHA256 and HMAC-SHA256 for root and chain derivation
- SHA-256 for identity fingerprints, transcript binding, integrity digests, and Merkle trees

At a high level:

- direct 1:1 chat is authenticated and ratcheted end-to-end
- direct file transfer is encrypted and signed before transport
- large-file transfer adds chunk hashes, Merkle proofs, and resumable session state
- DID-first remote contact works without local profile import by resolving a signed contact bundle over global discovery
- Safe mode keeps selected state on disk, but encrypts and reduces that state
- Ghost mode avoids the daemon's normal persistence paths and performs aggressive best-effort cleanup on exit

The most important caveat remains architectural: the embedded AI subsystem is a separate persistence domain. Safe/Ghost guarantees for the daemon do not automatically imply identical persistence behavior for AI conversation/session state.

The current direct-session security pipeline is best understood as a layered protocol chain rather than a single "encrypted chat" claim:

1. identity layer: each agent has Ed25519, X25519, and Kyber-1024 key material
2. discovery layer: a user-visible `did:qypha:...` resolves to a signed contact bundle containing a signed `DidProfile`
3. first-contact layer: the sender seals a signed `ContactRequest` to the recipient's X25519 + Kyber-1024 keys
4. bootstrap layer: peers exchange a signed handshake carrying X25519, Kyber-1024, ratchet bootstrap material, and transport/session hints
5. session layer: after bootstrap, direct 1:1 chat runs as ratcheted end-to-end encryption with Double Ratchet + AEGIS-256

This matters because Kyber-1024 is part of current identity and bootstrap expectations, but not a per-message KEM applied on every chat message. The post-quantum material is bound into session establishment; steady-state direct chat then uses ratcheted message keys.

## 3. Threat Model and Non-Goals

### 3.1 Intended protections

Qypha is designed to provide meaningful protection against:

- passive network surveillance
- active packet tampering and forged application traffic
- replay of previously valid messages
- unauthorized first contact without the relevant invite, bundle, or signed contact profile path
- disk inspection of Safe-mode persisted state without the agent's key material
- downgrade from hybrid/PQC-capable flows where strict privacy modes require PQC support
- many ordinary crash-dump, shell-history, temp-file, and clipboard residues, to the extent supported by the host OS and privilege level

### 3.2 Explicit non-goals

Qypha does not claim a formal guarantee against:

- a fully compromised host OS, kernel, or hypervisor
- malware already running with user or admin/root privilege
- hardware attacks, DMA attacks, cold-boot attacks, or malicious firmware
- all SSD and journaling filesystem remnants under all conditions
- all cloud-sync, backup, search indexing, or vendor-managed telemetry outside Qypha's control
- all persistence in the separate embedded AI subsystem

### 3.3 Open source and security

Qypha's cryptographic design does not depend on secrecy of the algorithms. The system is intended to remain secure when the protocol, message formats, and cryptographic choices are public. Security is expected to depend on key secrecy, signature verification, replay protection, and authenticated state transitions, not on obscurity.

## 4. Identity Model, DID Layers, and Key Material

### 4.1 Per-agent key material

Each agent identity includes:

- an Ed25519 signing keypair used for identity, signatures, DID binding, request verification, and signed profile verification
- an X25519 keypair used for classical key agreement and hybrid envelope construction
- a Kyber-1024 public/secret keypair used for post-quantum KEM material in hybrid bootstrap and hybrid transfer envelopes

These keys are generated per agent. They are not derived from the agent name, passphrase, machine name, or geographic location.

They also do not all play the same role at the same time:

- Ed25519 is the stable identity anchor
- X25519 + Kyber-1024 are the direct-contact and bootstrap encryption surfaces
- Double Ratchet message keys are derived later and are distinct from the long-term identity keys

### 4.2 Internal canonical DID

The internal canonical DID is derived from the Ed25519 verifying key fingerprint:

- `did:nxf:<sha256(ed25519_verifying_key)>`

This internal DID remains the canonical runtime identity used in multiple storage and routing paths.

### 4.3 User-visible contact DID

The user-visible contact DID is:

- `did:qypha:<base58(sha256(ed25519_verifying_key))>`

This is a shorter, user-facing representation of the same 256-bit identity fingerprint. It does not reduce entropy compared with the internal canonical DID; it only changes encoding.

### 4.4 DID uniqueness

Qypha DID uniqueness does not depend on the chosen agent name or passphrase. Two operators can create agents with the same display name and the same passphrase on different machines and still receive different DIDs, because the DID is bound to a freshly generated Ed25519 keypair rather than user-entered text.

In practical terms, DID collisions are governed by the 256-bit SHA-256 fingerprint space, not by usernames or passwords.

### 4.5 DID integrity checks

The codebase verifies that:

- a stored DID matches the Ed25519 verifying key derived from the identity file
- a published DID profile matches the included verifying key
- a user-visible `did:qypha:...` resolves back to the expected canonical DID

This prevents simple DID/key mismatch tampering.

### 4.6 Identity load and upgrade behavior

Current Qypha identities are expected to carry Kyber-1024 material, but the identity loader still contains compatibility logic for older stored identities.

In practice, the loader can encounter:

- an identity file with no Kyber secret/public material
- an identity file carrying an older Kyber parameter set

When this happens, the current load path upgrades the identity in memory by generating fresh Kyber-1024 material. This is intentionally separate from DID identity:

- the DID does not change, because the DID is derived from the Ed25519 verifying key
- the X25519 keypair also remains the same unless that part of the identity is separately upgraded
- the new Kyber-1024 material becomes the current bootstrap and hybrid-transfer surface

The operator must re-save the identity for the upgraded Kyber material to become the persisted on-disk state. So the compatibility behavior is:

- decode old identity
- generate/upgrade Kyber-1024 material if required
- continue using the stable Ed25519-bound DID
- persist the upgraded state only after a later save

## 5. Discovery, Reachability, and Contact Establishment

Qypha now separates identity lookup from first-contact transport.

### 5.1 DID-first architecture

In the current design, the short `did:qypha:...` is a lookup handle, not a self-contained invite blob. It does not itself carry the full contact profile, relay descriptor, or onboarding payload. Instead, it points to a signed contact bundle that can be independently resolved and verified.

The current DID-first path works as:

1. a user shares a short `did:qypha:...`
2. the sender resolves a signed contact bundle for that DID over the configured discovery plane
3. the sender verifies that the returned bundle matches the DID fingerprint
4. the sender extracts the recipient's signed `DidProfile`
5. the sender verifies that the profile signature and DID/verifying-key binding are valid
6. the sender uses that profile to deliver an encrypted first-contact request
7. the recipient accepts or rejects the request
8. a trusted direct session is promoted and secure handshake begins immediately

This means local `did_profile.json` import is no longer required for ordinary DID-first onboarding.

### 5.2 Signed DID profile contents

A `DidProfile` currently carries:

- canonical DID (`did:nxf:...`)
- Ed25519 verifying key
- X25519 public key
- Kyber-1024 public key (hex)
- creation time
- optional expiry
- advertised contact services
- Ed25519 signature over the canonical profile encoding

For current Qypha identities, the Kyber public key is part of the expected signed profile surface rather than a best-effort extension. Older serialized profiles may still decode for compatibility purposes, but bootstrap and verification treat missing Kyber material as invalid for current first-contact flows.

Advertised contact services can include:

- `IrohRelay`
- `TorMailbox`

### 5.3 Iroh discovery and relay-only public contact endpoints

The Internet-mode discovery path is deliberately relay-only for public contact exposure.

For public contact bundle discovery, Qypha:

- derives a deterministic public iroh endpoint secret from the contact DID
- binds an iroh endpoint with `clear_ip_transports()`
- advertises only relay addresses in the public endpoint
- rejects public iroh contact endpoints that contain direct or non-relay addresses

As a result, DID-first public discovery over iroh is designed so that the public discovery endpoint does not publish direct IP transport addresses.

### 5.4 Tor mailbox discovery

Tor discovery uses a mailbox-style contact service. A DID profile can advertise:

- onion address
- mailbox namespace
- onion service port

If a deterministic public Tor bundle pool is configured, Qypha can resolve DID-first public bundle data over that pool without relying on local profile import.

### 5.5 DID-first contact bundles

A contact bundle is a signed publication unit that binds:

- a user-visible `did:qypha:...`
- a signed `DidProfile`

The bundle response is accepted only if:

- the requested contact DID is well-formed
- the returned profile signature verifies
- the contact DID matches the returned profile's verifying key fingerprint

### 5.6 Contact requests

First-contact requests are not plaintext introductions. A contact request contains:

- sender DID profile
- request ID
- optional intro text
- optional invite token field
- transport policy
- timestamp
- Ed25519 signature

The contact request is then sealed inside a hybrid encrypted envelope for the recipient.

This sealed contact request should be thought of as a pre-session onboarding object, not as an ordinary chat message. It exists before the direct ratchet session is established and uses the recipient's signed profile material to create a hybrid bootstrap envelope.

### 5.7 Incoming-connect policy gate

Qypha also includes an operator-controlled policy layer for new first contact. This gate applies to:

- DID-first contact requests
- invite-based first-contact attempts

Operators can block new inbound first-contact requests:

- from one specific peer DID
- or globally for all new first-contact traffic

This is distinct from message cryptography. It is an admission-control policy layer that decides whether new contact attempts are surfaced, queued, or dropped before trust is established.

Persistence follows the Safe/Ghost model:

- Safe mode can persist the incoming-connect gate policy in encrypted agent state
- Ghost mode does not persist that policy on disk

## 6. Standard Direct Invites and Group Invites

Qypha currently has two distinct invite families, and they are not equivalent.

### 6.1 Standard direct invites (`PeerInvite`)

The standard direct invite path used by `/invite` still uses a signed binary `PeerInvite` envelope encoded as URL-safe base64.

A direct `PeerInvite` can carry:

- canonical DID
- peer identifier
- Ed25519 verifying key
- creation time
- random invite ID
- Ed25519 signature
- optional Tor onion address
- optional serialized iroh endpoint address
- onion port

Important consequence:

- standard direct invites are authenticated, but not confidential
- they may still carry routing metadata
- whether IP-like metadata appears depends on transport and privacy settings

For example:

- Tor direct invites can expose the onion service address
- LAN/TCP invites can expose TCP reachability if IP hiding is disabled
- iroh direct invites can embed an iroh endpoint descriptor; in privacy-hardened Internet mode, relay-only endpoint exposure is preferred

### 6.2 Minimal group invite token plus separate group bundle

Group onboarding is stricter and more modular.

The current group invite token (`GroupMailboxInvite`) is intentionally minimal and carries only:

- group ID
- anonymous-group flag
- creation time
- expiry
- issuer verifying key
- invite ID
- nonce
- signature

It does not embed:

- group display name
- mailbox endpoint string
- mailbox namespace
- mailbox capability secrets
- content crypto state

Those details live in a separate signed `GroupInviteBundle`, which can be resolved over the discovery plane.

### 6.3 Group invite bundle contents

A `GroupInviteBundle` can carry:

- invite ID
- group ID and optional group name
- anonymous-group flag
- join-locked flag
- mailbox descriptor
- mailbox capability
- optional group content crypto state
- optional anonymous writer state
- issuer DID or issuer verifying-key identity
- creation time and expiry
- signature

This split keeps the operator-visible group invite code short while still allowing a richer signed onboarding bundle to be discovered separately.

### 6.4 Security interpretation

The correct public framing is:

- direct peer invite: compact authenticated route-bearing invite
- group invite: compact authenticated token plus separately resolved signed bundle
- DID-first remote contact: short DID plus globally resolved signed contact bundle

## 7. Application Request Authentication and Message Admission

### 7.1 Signed `AgentRequest`

Qypha does not trust transport reachability alone. Normal application traffic is wrapped in `AgentRequest`, which carries an Ed25519 signature over:

- `msg_type || payload || nonce || timestamp`

This gives the daemon a stable application-layer authenticity check even after a transport session already exists.

### 7.2 Handshake payload contents

The handshake payload can carry:

- X25519 public key
- Kyber-1024 public key
- optional Ed25519 verifying key
- ratchet DH public material
- hybrid ratchet KDF suite information
- optional Kyber ciphertext for hybrid bootstrap
- AEGIS capability advertisement
- optional invite code / proof data
- optional iroh reconnect endpoint data
- handshake acknowledgement identifiers

In practical terms, the current handshake has three jobs at once:

1. authenticate who this peer claims to be
2. advertise the key material required for secure direct-session establishment
3. carry the direct-chat ratchet bootstrap hints needed to transition from "trusted contact" into "live E2EE session"

The receiver uses this handshake material to bind:

- peer identity
- signature key
- classical encryption key
- post-quantum key material
- ratchet bootstrap state

In the current bootstrap path, the public Kyber key is not just advisory capability metadata. It is treated as required bootstrap material for direct session establishment; legacy payloads that decode without it are rejected rather than silently accepted.

The handshake is therefore not just a transport hello. It is the signed bootstrap surface that ties together identity continuity, hybrid key material, and ratchet initialization.

### 7.3 Replay and freshness

Replay protection applies to application requests. Qypha checks:

- nonce reuse
- timestamp freshness
- TTL expiration
- implausible future timestamps

If freshness checks fail, the message is rejected.

### 7.4 Rate limiting

The daemon also enforces:

- ordinary per-agent rate limiting
- higher-throughput limits for chunked transfer flows

These are not replacements for cryptography, but they materially improve resilience against abuse and spam.

## 8. 1:1 Contact Establishment, Handshake, and Key Continuity

### 8.1 DID-first first contact

When `/connect did:qypha:...` is used, Qypha:

1. resolves the signed contact bundle
2. verifies the returned `DidProfile`
3. encrypts and signs a `ContactRequest`
4. delivers it via live route, iroh relay contact, or Tor mailbox fallback
5. waits for `ContactAccept` or `ContactReject`
6. promotes the peer into trusted state and primes direct handshake

Operationally, this means DID-first contact is a two-phase process:

- phase 1: authenticated contact establishment using the signed profile and sealed request/accept path
- phase 2: signed hybrid bootstrap into a direct ratcheted session

This separation is important because "contact established" and "ratcheted chat session active" are related but distinct states in the implementation.

### 8.2 Encrypted contact request envelopes

Contact requests, accepts, and rejects are not sent as raw JSON. They are sealed using the hybrid message envelope machinery, which can combine:

- recipient X25519 public key
- recipient Kyber public key
- AEGIS-256 inner encryption
- XChaCha20-Poly1305 outer cascade encryption in hybrid paths

This is the main place where the whitepaper should distinguish bootstrap confidentiality from ordinary chat confidentiality:

- first-contact envelopes use hybrid bootstrap encryption tied to long-term profile keys
- later direct chat messages use ratcheted message keys derived after the bootstrap completes

### 8.3 Strict PQC behavior in privacy-hardened paths

The code enforces strict PQC expectations at the identity/profile/bootstrap boundary. In practice, current DID-first contact establishment and direct-session bootstrap expect peers to provide hybrid-capable material rather than silently continuing with a weaker classical-only bootstrap.

This is important because the code is not merely "Kyber-capable". In privacy-hardened contexts it actively tries to avoid silent downgrade.

### 8.4 Key continuity / MITM detection

For known peers, the incoming handshake path compares newly advertised key material against the previously trusted material. Unexpected changes to X25519 or Kyber public keys are treated as potential MITM or continuity failures rather than being silently accepted.

This provides a key-continuity check in addition to signature verification.

## 9. Direct 1:1 Chat Security

### 9.1 Ratcheted chat is the intended direct-message path

Direct 1:1 chat uses a Signal-style Double Ratchet. The current implementation includes:

- X25519 DH ratchet steps
- HKDF-SHA256 for root chain derivation
- HMAC-SHA256 for sending/receiving chain advancement
- AEGIS-256 for per-message encryption
- skipped-message-key handling with bounded storage

The important practical clarification is that Kyber-1024 is not run as a fresh KEM on every ordinary chat message. Instead:

- Kyber-1024 contributes to current hybrid session bootstrap
- Double Ratchet derives the live per-message keys after bootstrap
- AEGIS-256 protects the actual direct-chat payloads on a per-message basis

This should be read separately from transport security. In Internet mode, iroh can still provide authenticated session transport, but Qypha's normal direct-chat payload is not described as a second simultaneous cascade AEAD layer. The application-layer direct-chat primitive remains ratcheted AEGIS-256, while transport protection is an additional lower-layer property.

### 9.2 Ratchet bootstrap material

The direct-chat ratchet seed is bound to both classical and post-quantum material during current bootstrap. The bootstrap transcript binds:

- both DIDs
- both verifying keys
- both X25519 public keys
- both ratchet public keys
- hybrid shared secret material when present

This prevents the ratchet seed from being a loose detached secret. It is transcript-bound to the actual negotiated peer identities and key advertisements.

In current Qypha terms, this is the point where "X25519 + Kyber-1024 hybrid bootstrap" becomes "signed bootstrap + ratcheted E2EE chat". The long-term identity/profile layer and the later per-message ratchet layer are intentionally connected, but they are not the same primitive.

### 9.3 Legacy chat rejection

The incoming direct-chat path distinguishes between:

- ratcheted chat payloads
- legacy envelopes
- invalid/unexpected payloads

Current logic prefers the ratcheted path and rejects weaker or incompatible legacy paths when ratcheted E2EE is required.

### 9.4 Security properties of direct chat

The intended direct-chat guarantees are:

- sender authenticity through Ed25519-signed admission and stored verifying keys
- confidentiality through ratcheted per-message AEGIS-256 keys
- forward secrecy for older messages after ratchet advancement
- post-compromise recovery after later successful DH ratchet events
- replay resistance through request-level nonce/time checks

## 10. Group and Mailbox Security

### 10.1 Mailbox bootstrap tokens

Mailbox bootstrap tokens are signed capability documents. Validation checks include:

- scope kind and scope ID
- namespace
- capability ID
- access key digest
- auth token digest
- issuance time and expiry
- issuer verifying key
- proof-of-work material where configured
- signature validity

This means mailbox access is not granted merely by knowing an endpoint string.

### 10.2 Group content crypto state

Anonymous and mailbox-backed groups can advertise rotating group content-crypto state and anonymous writer state. Current advertised suites include:

- `epoch_aegis256` for content crypto
- `epoch_hmac_sha256` for anonymous writer credentials

This allows group content protection and anonymous writer authorization to rotate across mailbox epochs instead of depending on a single forever-secret.

### 10.3 Group inbox security boundary

Mailbox or Tor routing changes reachability and metadata characteristics, but it does not replace application-layer checks. Signed payloads, bundle verification, and advertised crypto state remain part of the trust boundary.

### 10.4 Hybrid-encrypted group control-plane secrets

Kyber-1024 is not used only for direct 1:1 onboarding and file transfer. The current group/mailbox control plane also uses hybrid X25519 + Kyber-1024 envelopes for several recipient-targeted secrets.

Important current examples include:

- fast file grant secrets for group-scoped relay/file-download authorization
- direct handshake offers that carry an invite code toward a specific member
- mailbox rotation secrets that carry the next session bundle for a specific target member

These flows follow a common pattern:

1. a signed outer mailbox/group payload identifies the event
2. the recipient-specific secret is serialized separately
3. that secret is hybrid-encrypted to the target member's X25519 and Kyber public keys
4. the target member decrypts it using local X25519 and Kyber secret material

This matters because the mailbox audience may observe that a grant, direct-handshake offer, or rotation event exists, while the sensitive inner secret remains hidden from non-target members. In other words:

- mailbox control-plane visibility does not imply inner secret visibility
- the confidential part of these targeted group control messages is still protected by the same hybrid envelope machinery used elsewhere in Qypha

## 11. File Transfer Architecture

Qypha file transfer has three main layers:

1. artifact packaging
2. artifact or chunk encryption
3. transport delivery

The transport may be live peer, mailbox-assisted, or relay-assisted, but encryption and integrity are applied before the transport layer sees the file payload.

### 11.1 Packaging behavior

For small/inline transfer:

- directories and most regular files are packed into an archive payload
- already compressed file types may travel as raw payloads instead of being recompressed

For large transfer:

- packed data is split into chunks
- per-chunk hashes and a Merkle tree are computed
- transfer session metadata is created separately from raw chunk data

### 11.2 Monolithic / inline direct transfer

For smaller file transfers, the sender:

1. packs the source path
2. computes plaintext SHA-256
3. requires recipient Kyber public material for current PQC-hardened transfer path
4. encrypts the payload with a fresh symmetric key using AEGIS-256
5. wraps that key in a hybrid envelope using X25519 + Kyber-1024
6. signs the plaintext hash with Ed25519
7. pads the encrypted payload into bucketed sizes before transport

So the direct-transfer path is not "chat encryption reused for files". It is a separate hybrid-enveloped artifact path with its own payload key, signature, and integrity checks.

The receiver:

1. verifies the sender signature
2. decrypts the hybrid key envelope
3. decrypts the artifact payload
4. recomputes and verifies the plaintext SHA-256
5. unpacks the artifact

### 11.3 Chunked transfer

For larger transfers, Qypha uses a resumable session model.

Session preparation includes:

- chunk splitting
- per-chunk SHA-256 hashes
- Merkle root computation
- overall plaintext SHA-256
- session ID and resume token

Each encrypted chunk carries:

- session ID
- chunk index / total chunk count
- encrypted chunk bytes
- key envelope bytes
- sender signature
- Merkle proof
- chunk SHA-256

The receiver validates:

- Merkle proof membership
- sender signature
- chunk hash
- final reconstructed-file hash and Merkle root

### 11.4 Wire-size padding

Qypha includes traffic-analysis resistance measures in file transfer:

- monolithic transfers are padded to bucket sizes before transport
- chunked transfers use a fixed padded block size of 4.25 MB on the wire

Padding does not make transfer metadata disappear, but it reduces exact size leakage.

### 11.5 Chunked transfer persistence and Ghost-mode staging

In ordinary config defaults, zero-trace disk staging for chunked transfers is disabled.

However, the Ghost launch flow intentionally makes a different tradeoff by default:

- it creates a private temporary runtime root
- it stages large transfer chunks in secure temporary storage to reduce RAM pressure
- it disables resumable session persistence
- it wipes transfer temp roots on exit

This is an implementation choice to make very large Ghost transfers practical while still confining staging to a volatile, aggressively cleaned runtime area. Operators can further tune this behavior.

### 11.6 Incoming transfer approval policy

Incoming file transfer is not purely transport-driven. Qypha also applies an explicit receiver policy layer.

For direct incoming transfer, the receiver can operate in one of two policy states per sender:

- ask every time
- always accept

In practice this means:

- unknown or default senders require explicit approval before file transfer proceeds
- a sender can be promoted into an always-accept policy for later transfers
- the receiver can switch a sender back to ask-on-each-transfer

This policy layer exists in addition to encryption, signatures, and chunk proofs. It is a receiver-controlled admission gate for incoming file payloads, not a substitute for end-to-end cryptographic protection.

### 11.7 Relay and mailbox transfer paths

Qypha can deliver file traffic through:

- direct peer transport
- mailbox-assisted group delivery
- fast iroh relay-assisted group transfer reuse

The important security property is that the relay path does not replace artifact encryption. Relay changes delivery, not payload confidentiality.

### 11.8 Transfer metadata caveat

Not all transfer metadata is equally hidden across all paths.

For example, current transfer payload structures can still expose recipient-visible metadata such as:

- filename
- classification
- encrypted size

Chunked v2 paths include support for sealed metadata, but metadata minimization is not uniform across every transfer path. The correct claim is therefore:

- file content is strongly protected end-to-end
- some transfer metadata remains protocol-visible by design

## 12. Iroh, Relay Use, and Internet Privacy Behavior

### 12.1 Internet mode is not "plaintext internet mode"

Internet mode does not replace application-layer security. Even when iroh provides authenticated session transport, Qypha still signs application requests and separately encrypts direct chat and artifact payloads.

### 12.2 Public iroh discovery is relay-only

Public contact bundle discovery and public contact endpoints are designed to be relay-only. Qypha explicitly normalizes or rejects public endpoint advertisements that include direct transport addresses in this discovery plane.

### 12.3 Safe-mode iroh behavior

When Safe mode is active and transport mode is Internet, Qypha:

- disables mDNS
- disables Kademlia
- forces iroh relay to remain enabled
- disables direct iroh paths
- keeps `hide_ip = true`

This is a deliberate privacy tradeoff: less reachability optimization, more metadata protection.

### 12.4 Direct iroh invites versus DID-first discovery

A subtle but important distinction exists:

- DID-first public discovery is relay-only by design
- standard direct invites may still carry an iroh endpoint descriptor

Therefore the whitepaper should not claim that every invite is metadata-free. The strongest privacy claims belong to DID-first bundle discovery and privacy-hardened relay-only Internet mode, not to every possible invite UX path.

### 12.5 Cover traffic and timing-analysis hardening

Qypha also exposes a configurable cover-traffic layer intended to make timing analysis harder.

The current configuration surface includes:

- `auto` mode
- `always` mode
- `off` mode
- configurable interval
- configurable packet size

In current defaults, cover traffic is described conservatively:

- it is a timing-noise hardening measure
- it is not a replacement for end-to-end encryption
- it does not make all metadata disappear
- it should be described as best-effort privacy hardening unless separately audited in more depth

## 13. Safe Mode

Safe mode should be understood as privacy-hardened encrypted persistence, not zero persistence.

### 13.1 Safe-mode runtime behavior

Safe mode currently:

- disables mDNS
- disables Kademlia
- forces relay-only Internet behavior when Internet transport is selected
- keeps `hide_ip = true`
- disables REPL command history
- disables core dumps
- attempts key memory locking where possible
- avoids normal ratchet-session persistence
- reduces durable metadata exposure compared with a conventional persistent daemon

### 13.2 What Safe mode can persist

Safe mode can persist encrypted state such as:

- known-peer store
- used-invite cache
- iroh continuity material
- selected mailbox/group state
- encrypted audit log
- encrypted config fields

### 13.3 What Safe mode does not promise

Safe mode does not promise:

- RAM-only operation
- zero logs
- zero disk traces
- zero metadata

Its correct description is:

- persistent mode
- encrypted persistence
- reduced discovery and metadata exposure
- privacy-hardened defaults

## 14. Ghost Mode

Ghost mode is the daemon's strongest privacy posture, but it must be described carefully.

### 14.1 What Ghost disables

Ghost mode disables or avoids persistence for:

- audit logs
- known-peer store
- used-invite store
- mailbox/group store
- ratchet persistence
- normal reconnect seeding
- standard durable receive paths

The audit object in Ghost mode has no file path and zeroed key material.

For ordinary 1:1 chat, live session state remains memory-resident in Ghost mode: ratchet state, message keys, pending message context, and active peer session state are intended to stay in RAM rather than in the daemon's normal durable persistence paths. This should be distinguished from large file transfer staging, which may still use secure temporary storage to reduce RAM pressure.

### 14.2 Ghost launch behavior and transport

In current launch flows, Ghost is treated as an OPSEC-first mode. When Ghost is launched through the interactive Ghost path, non-anonymizing transports are warned against and the flow forces Tor for IP anonymity.

### 14.3 Runtime hardening in Ghost

Ghost mode applies a stronger hardening profile, including:

- core dump disablement
- Linux `mlockall` attempt for full memory locking where available
- fallback key-memory locking when full lock fails
- `MADV_DONTDUMP` on Linux for key memory
- emergency panic hook cleanup path
- startup janitor for stale zero-trace temp artifacts

### 14.4 Ghost file handling

Ghost mode keeps transfer and handoff artifacts under a dedicated temporary runtime root such as:

- ghost receive root
- ghost handoff root
- chunk transfer temp root
- transfer session temp root

These are wiped during Ghost cleanup.

### 14.5 Ghost cleanup and anti-forensic behavior

On shutdown, Ghost performs best-effort cleanup including:

- terminal screen clear
- terminal scrollback purge
- shell-history scrubbing
- environment-variable scrubbing
- DNS cache flush
- secure wipe of ghost receive, handoff, transfer, and session roots
- secure wipe of temp directories containing Qypha traces
- platform-specific cleanup of recent files, crash dumps, clipboard state, and selected logs

Platform-specific logic includes dedicated cleanup routines for:

- macOS
- Linux
- Windows

These routines attempt to clean artifacts such as:

- Terminal/iTerm saved state
- GNOME/KDE recent-items state
- PowerShell history and Windows Recent/Jump Lists
- crash reports and coredumps
- clipboard history and timeline caches
- selected syslog/journal/Event Log traces
- temp directories and app-specific caches

### 14.6 Secure wipe model

Qypha secure wipe is described in code as:

- random overwrite
- truncate-to-zero / TRIM trigger
- unlink

On SSDs, this is still best-effort. With full-disk encryption active, the design becomes materially stronger because any stale pages remain encrypted under the host FDE layer.

### 14.7 Important Ghost caveats

Ghost should be described as:

- no intended daemon persistence
- aggressive best-effort cleanup
- stronger memory and runtime hardening

It should not be described as a mathematical proof that no forensic evidence can remain under all host conditions.

Without admin/root privileges, some OS-owned traces cannot be fully cleaned.

## 15. At-Rest Encryption and Persistence Design

### 15.1 Encrypted config values

Encrypted config fields use:

- Argon2id
- AES-256-GCM
- random per-value salt and nonce
- authenticated additional data `Qypha-Config-Encryption-v2`

The current Argon2id parameters are intentionally strong:

- memory cost: 256 MiB
- iterations: 4
- parallelism: 4

### 15.2 Agent-scoped persisted blobs

Encrypted persisted state blobs use:

- AES-256-GCM
- blob magic `QLPSTV1!`
- scope-bound AAD
- HKDF-SHA256 derived keys

Persistence keys are derived from agent secret material and a scope label, rather than from a global app-wide static key.

### 15.3 Audit root-key derivation

Kyber also appears in a local at-rest context, not only in network bootstrap and transfer paths.

The current audit root key is derived from:

- the agent's X25519 secret key
- the agent's Kyber secret key when present
- a fixed domain-separation label for the audit log

This means audit-log confidentiality/integrity does not depend on a single app-global password or static constant. Instead, it is tied back to agent-held secret material.

This is a separate use of Kyber from message bootstrap:

- it is local persistence-key derivation, not a network handshake
- it does not mean the audit log is "Kyber-encrypted on the wire"
- it does mean the post-quantum secret material influences a local encrypted state root

### 15.4 Known-peer store

Safe-mode known peers can persist:

- DID
- name/role
- peer ID
- optional onion/TCP/iroh reconnect coordinates
- optional X25519 public key
- optional Kyber public key
- last-seen time
- auto-reconnect flag

Ghost mode stores none of this on disk.

### 15.5 Replay guard and invite persistence

Replay windows, used-invite caches, and related persisted control-plane blobs follow the same broad rule:

- Safe can persist selected control-plane state, encrypted at rest
- Ghost does not persist those stores

## 16. Audit Logging

### 16.1 Safe-mode audit design

Safe-mode audit logging is not plaintext logging. Audit entries are:

- chained with SHA-256 over previous hash, sequence, timestamp, type, actor, and details
- stored in an encrypted binary log
- protected with HMAC-derived integrity material
- privacy-hardened by hashing/redacting actor DID and details before storage

### 16.2 Ghost audit behavior

Ghost-mode audit is effectively disabled:

- no audit file path
- zeroed audit keys
- no owner DID retained in the audit object

## 17. Memory Hygiene and Shutdown Behavior

Qypha explicitly zeroizes sensitive material where possible, including:

- signing key material
- X25519 secret material
- Kyber secret material
- ratchet chain/message keys
- some persistence-key material and transient keying buffers

It also attempts:

- core-dump disablement
- memory locking
- no-history interactive behavior
- sensitive temp-root cleanup

These measures materially improve resistance to casual crash-dump and swap exposure, but they are still bounded by host OS privilege and policy.

## 18. Embedded AI Runtime Caveat

This is the most important architectural caveat in the project.

The embedded AI subsystem is a separate persistence domain from the network daemon. In practice, it maintains its own state roots, session files, thread history, and memory inputs. That means:

- Safe/Ghost guarantees for the daemon do not automatically cover embedded AI thread/session persistence
- operators who need full zero-persistence semantics must separately evaluate, constrain, or wipe the AI runtime state roots

The correct public claim is therefore:

- Qypha's daemon can operate in Safe or Ghost modes
- the embedded AI runtime is adjacent, not identical, in its persistence model

## 19. Security Properties and Caveats

### 19.1 High-confidence current properties

The current branch strongly supports the following claims:

- authenticated application requests using Ed25519 signatures
- direct 1:1 ratcheted E2EE chat
- hybrid-capable first-contact and handshake material
- relay-only DID-first public iroh discovery endpoints
- signed DID profiles and signed contact bundles
- signed mailbox capabilities and signed group invite bundles
- signed and encrypted file transfer with chunk proofs for large files
- encrypted Safe-mode persistence
- no normal daemon persistence in Ghost mode

### 19.2 Best-effort properties

The following are meaningful protections but should still be described as best-effort:

- shell-history cleanup
- terminal scrollback purge
- temp-root secure wipe on commodity SSDs
- DNS cache flushes
- recent-files and OS log cleanup
- some platform-specific forensic suppression paths

### 19.3 Current caveats

The present branch also has important caveats that should be documented honestly:

- direct peer invites are authenticated but may still carry route metadata
- not every transfer path hides every metadata field
- Ghost cleanup strength depends heavily on host privilege and FDE
- the embedded AI runtime is a separate persistence domain
- internal canonical DID (`did:nxf:...`) still exists behind the user-visible contact DID layer
- some advanced shadow/cover-traffic behavior exists, but should be described conservatively unless separately audited

## 20. Recommended Public Positioning

The most accurate public description of Qypha today is:

- a decentralized cryptographic network for humans and AI agents
- authenticated agent-to-agent messaging with ratcheted 1:1 E2EE
- DID-first remote contact over signed bundle discovery
- signed invite and mailbox capability model for onboarding and groups
- encrypted artifact and chunked file transfer with integrity proofs
- Safe mode for privacy-hardened encrypted persistence
- Ghost mode for ephemeral daemon operation with aggressive best-effort cleanup

Avoid the following overclaims unless the implementation changes further:

- "all invites are metadata-free"
- "Ghost proves zero forensic residue under all conditions"
- "all AI memory is RAM-only in Ghost"
- "all metadata is hidden in every transfer path"
- "every path is post-quantum only under every runtime mode"


