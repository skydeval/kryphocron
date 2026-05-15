//! §7.3 DID resolution + §7.7 federation-peer-trust trait
//! surfaces.
//!
//! Phase 1 shipped trait shapes; Phase 4c lands the §7.3 default
//! resolver with two caches (per-request + trust-root), key-
//! rotation detection, and operator-initiated invalidation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use thiserror::Error;

use crate::audit::{SubstrateAuditEvent, SubstrateAuditSink};
use crate::identity::{KeyId, PublicKey, TraceId};
use crate::proto::Did;

/// Substrate-side hard ceiling on the per-request DID document
/// cache TTL (§7.3). One hour. Operators can configure tighter
/// caching via [`ResolverConfig::max_document_cache_age`] but
/// not looser; the ceiling protects against stale-key
/// vulnerabilities where an attacker compromises a key, the
/// legitimate owner rotates it, but stale cached documents still
/// present the compromised key as valid.
pub const MAX_DID_DOCUMENT_CACHE_AGE: Duration = Duration::from_secs(3600);

/// Substrate-side hard ceiling on the trust-root key cache TTL
/// (§7.3 / §7.4). 60 seconds — a separate, much-shorter cache
/// from the per-request DID document cache, used only by trust-
/// declaration verification. Bounds the cache × declaration-
/// validity inversion window per the round-3 patch discipline.
pub const MAX_TRUST_ROOT_CACHE_AGE: Duration = Duration::from_secs(60);

/// DID document subset the substrate consumes (§7.3).
///
/// Phase 1 shipped a minimal shape; Phase 4c lands the §7.3
/// fields the cache discipline requires (`resolved_at`,
/// `resolver_cache_max_age`) plus the §7.3-prose service /
/// also-known-as additions. The `verification_methods` /
/// `rotation_history` shape is preserved from Phase 1 for
/// continuity with Phase 4a/4b's signing-key-selection helpers.
/// Chainlink for Phase 6: §7.3's prose uses
/// `Vec<VerificationMethod>` for `verification_methods`; the
/// in-crate shape carries `Vec<(KeyId, PublicKey)>` instead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DidDocument {
    /// The DID this document describes.
    pub did: Did,
    /// Currently-active verification methods keyed by key id.
    pub verification_methods: Vec<(KeyId, PublicKey)>,
    /// Historical key rotations, oldest first.
    pub rotation_history: Vec<(KeyId, PublicKey)>,
    /// Service endpoints declared by the document (§7.3). Empty
    /// for documents whose method doesn't expose service entries.
    pub services: Vec<DidService>,
    /// Alternative names for the principal (§7.3). Typically
    /// did:plc documents carry a handle here; did:web doesn't.
    pub also_known_as: Vec<String>,
    /// Wallclock at which this document was resolved.
    pub resolved_at: SystemTime,
    /// Document-declared maximum cache age, capped by
    /// [`MAX_DID_DOCUMENT_CACHE_AGE`] downstream.
    pub resolver_cache_max_age: Duration,
}

/// Service endpoint declared by a DID document (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DidService {
    /// Service identifier (URI fragment), e.g. `"#atproto_pds"`.
    pub id: String,
    /// Service type, e.g. `"AtprotoPersonalDataServer"`.
    pub service_type: String,
    /// Endpoint URI.
    pub endpoint: String,
}

/// DID resolution failure (§7.3).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DidResolutionError {
    /// DID does not exist in the chosen registry.
    #[error("DID not found")]
    NotFound,
    /// DID document was structurally malformed.
    #[error("DID document malformed")]
    Malformed,
    /// Resolver returned no answer within `deadline`.
    #[error("DID resolution exceeded deadline")]
    DeadlineExceeded,
    /// DID method (did:plc, did:web, …) is not supported by the
    /// configured resolver.
    #[error("DID method not supported: {0}")]
    MethodNotSupported(String),
    /// Upstream resolution infrastructure failed.
    #[error("DID resolution upstream error: {0}")]
    UpstreamError(String),
    /// DID has been tombstoned (`did:plc` supports tombstones).
    /// Once tombstoned, the resolver caches the tombstone and
    /// rejects future resolutions with the same error until
    /// operator-initiated invalidation explicitly removes the
    /// cached entry. Phase 4c addition.
    #[error("DID tombstoned")]
    Tombstoned,
}

/// Asynchronous DID resolver (§7.3).
///
/// All methods accept a `deadline: Instant`. Implementations
/// **must** return a structured result rather than blocking past
/// the deadline. Resolver implementations backed by external
/// services (PLC directory HTTP, did:web HTTPS fetch) honor the
/// deadline against upstream latency.
///
/// All methods also accept a `trace_id: TraceId` parameter for
/// audit-event correlation: when [`DefaultDidResolver`] detects
/// rotation or processes invalidation it emits
/// [`crate::audit::SubstrateAuditEvent::DidDocumentRotated`] /
/// `DidDocumentInvalidated`, and the audit event must be
/// attributable to the request that triggered the cache miss
/// (or, for invalidation, the operator action). Phase 4d adds
/// the parameter; the resolver-internal audit-emit sites
/// previously used a placeholder zero-id (chainlink #41).
///
/// Phase 4c lands [`DefaultDidResolver`] as a substrate-side
/// default; operators can substitute their own implementations
/// when they want different cache or transport behavior.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// Resolve `did` to a [`DidDocument`]. The `trace_id` is used
    /// to attribute any audit events emitted as a side effect of
    /// the resolution (rotation detection in particular).
    async fn resolve(
        &self,
        did: &Did,
        deadline: Instant,
        trace_id: TraceId,
    ) -> Result<DidDocument, DidResolutionError>;

    /// Invalidate the cached document for `did`. Operators use
    /// this on out-of-band signals (security advisory, user
    /// report). The `trace_id` is used to attribute the
    /// invalidation audit event to the operator action.
    async fn invalidate(&self, did: &Did, trace_id: TraceId);

    /// Return the DID methods this resolver can handle (§7.3).
    /// Default implementation returns `&["plc", "web"]` —
    /// resolvers supporting other methods override.
    fn supported_methods(&self) -> &[&'static str] {
        &["plc", "web"]
    }
}

// ============================================================
// §7.3 — DefaultDidResolver, HttpDidFetcher, two caches.
// ============================================================

/// Content-type discriminator on raw DID documents fetched from
/// upstream (§7.3). DID documents are JSON regardless of method;
/// this discriminator records the MIME type the upstream returned
/// so the resolver can route to the right parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentType {
    /// `application/json`.
    ApplicationJson,
    /// `application/did+json`.
    ApplicationDidJson,
}

/// Raw DID document bytes returned by an [`HttpDidFetcher`]
/// (§7.3). The substrate parses these into a [`DidDocument`]
/// inside the default resolver — the fetcher's job is just
/// transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDidDoc {
    /// Raw bytes, expected to be UTF-8 JSON per the W3C DID spec.
    pub bytes: Vec<u8>,
    /// MIME type the upstream returned.
    pub content_type: ContentType,
}

/// Operator-supplied transport layer for DID document fetching
/// (§7.3).
///
/// The crate ships [`DefaultDidResolver`]'s caching, parsing, and
/// rotation-detection machinery; operators bring their own HTTP
/// client (reqwest, hyper, etc.) by implementing this trait. The
/// substrate doesn't bake in an HTTP-client choice — operators
/// running in restricted environments (no network, custom
/// transports) substitute appropriate implementations.
///
/// Both methods take a `deadline: Instant` and MUST return
/// [`DidResolutionError::DeadlineExceeded`] rather than blocking
/// past it.
#[async_trait]
pub trait HttpDidFetcher: Send + Sync {
    /// Fetch a `did:plc` document from the configured PLC
    /// directory.
    async fn fetch_plc(
        &self,
        did: &Did,
        deadline: Instant,
    ) -> Result<RawDidDoc, DidResolutionError>;

    /// Fetch a `did:web` document by its W3C-spec well-known URL.
    async fn fetch_web(
        &self,
        did: &Did,
        deadline: Instant,
    ) -> Result<RawDidDoc, DidResolutionError>;
}

/// Operator-tunable configuration for [`DefaultDidResolver`]
/// (§7.3 round-3 patch).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolverConfig {
    /// Per-request DID document cache TTL ceiling. Capped at
    /// [`MAX_DID_DOCUMENT_CACHE_AGE`] = 1 hour. Operators may
    /// configure tighter, not looser.
    pub max_document_cache_age: Duration,
    /// Trust-root key cache TTL. Capped at
    /// [`MAX_TRUST_ROOT_CACHE_AGE`] = 60 seconds. Operators may
    /// configure tighter, not looser.
    pub max_trust_root_cache_age: Duration,
    /// PLC directory URL the [`HttpDidFetcher::fetch_plc`] target
    /// should use. Operator-configurable; defaults to ATProto
    /// convention.
    pub plc_directory_url: String,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            max_document_cache_age: MAX_DID_DOCUMENT_CACHE_AGE,
            max_trust_root_cache_age: MAX_TRUST_ROOT_CACHE_AGE,
            plc_directory_url: "https://plc.directory".to_string(),
        }
    }
}

/// One entry in the resolver cache. `Live` caches a successful
/// resolution; `Tombstoned` caches a `did:plc` tombstone (which
/// is permanent until operator-initiated invalidation).
#[derive(Debug, Clone)]
enum CachedEntry {
    Live {
        document: DidDocument,
        expires_at: Instant,
    },
    Tombstoned,
}

/// In-memory two-cache resolver default (§7.3).
///
/// The struct carries:
/// - The operator-supplied [`HttpDidFetcher`].
/// - A per-request DID-document cache (1-hour TTL ceiling per
///   §7.3) used by `resolve()`.
/// - A trust-root key cache (60-second TTL per round-3 patch)
///   used by [`Self::resolve_for_trust_root`].
/// - Optional [`SubstrateAuditSink`] reference for emitting
///   `DidDocumentRotated` / `DidDocumentInvalidated` events. If
///   `None`, the resolver still detects rotations and
///   invalidations but does not emit audit events.
///
/// The two caches are separate code paths even though they sit
/// behind the same [`DidResolver`] trait. Per §7.3's
/// "the trait does not expose this distinction": callers who
/// need the trust-root cache invoke
/// [`Self::resolve_for_trust_root`] (an inherent method, not on
/// the trait); all other callers go through `resolve()`.
pub struct DefaultDidResolver<F: HttpDidFetcher> {
    fetcher: F,
    config: ResolverConfig,
    document_cache: Mutex<HashMap<Did, CachedEntry>>,
    trust_root_cache: Mutex<HashMap<Did, CachedEntry>>,
    audit_sink: Option<Arc<dyn SubstrateAuditSink>>,
}

impl<F: HttpDidFetcher> DefaultDidResolver<F> {
    /// Construct a resolver with default config and no audit sink.
    /// Tests and lightweight deployments use this constructor.
    #[must_use]
    pub fn new(fetcher: F) -> Self {
        Self::with_config(fetcher, ResolverConfig::default(), None)
    }

    /// Construct a resolver with explicit config and an optional
    /// audit sink. Operators wiring `DidDocumentRotated` /
    /// `DidDocumentInvalidated` event emission supply the sink.
    #[must_use]
    pub fn with_config(
        fetcher: F,
        config: ResolverConfig,
        audit_sink: Option<Arc<dyn SubstrateAuditSink>>,
    ) -> Self {
        DefaultDidResolver {
            fetcher,
            config,
            document_cache: Mutex::new(HashMap::new()),
            trust_root_cache: Mutex::new(HashMap::new()),
            audit_sink,
        }
    }

    /// Per-request DID document resolution (the trait-side
    /// `resolve` body factored out for sharing with the
    /// trust-root variant).
    async fn resolve_with_cache(
        &self,
        did: &Did,
        deadline: Instant,
        trace_id: TraceId,
        cache: &Mutex<HashMap<Did, CachedEntry>>,
        cache_max_age: Duration,
    ) -> Result<DidDocument, DidResolutionError> {
        // Cache lookup.
        {
            let guard = cache
                .lock()
                .map_err(|_| DidResolutionError::UpstreamError("cache poisoned".into()))?;
            match guard.get(did) {
                Some(CachedEntry::Tombstoned) => {
                    return Err(DidResolutionError::Tombstoned);
                }
                Some(CachedEntry::Live { document, expires_at })
                    if Instant::now() < *expires_at =>
                {
                    return Ok(document.clone());
                }
                _ => {
                    // Cache miss or stale; fall through to re-fetch.
                }
            }
        }

        // Cache miss or stale: fetch fresh.
        let raw = match did_method(did) {
            "plc" => self.fetcher.fetch_plc(did, deadline).await,
            "web" => self.fetcher.fetch_web(did, deadline).await,
            other => {
                return Err(DidResolutionError::MethodNotSupported(other.to_string()))
            }
        };
        let raw = match raw {
            Ok(r) => r,
            Err(DidResolutionError::Tombstoned) => {
                // Cache the tombstone permanently (until operator
                // invalidation).
                if let Ok(mut guard) = cache.lock() {
                    guard.insert(did.clone(), CachedEntry::Tombstoned);
                }
                return Err(DidResolutionError::Tombstoned);
            }
            Err(other) => return Err(other),
        };

        let document = parse_did_document(did, &raw)?;

        // Rotation detection: if the cache had a Live entry whose
        // verification_methods differ, emit DidDocumentRotated
        // before swapping in the new document.
        let previous = {
            cache
                .lock()
                .ok()
                .and_then(|g| match g.get(did) {
                    Some(CachedEntry::Live { document, .. }) => Some(document.clone()),
                    _ => None,
                })
        };
        if let Some(prev) = &previous {
            if prev.verification_methods != document.verification_methods {
                self.emit_rotation_audit(did, prev, &document, trace_id);
            }
        }

        // Store in cache.
        let ttl = document.resolver_cache_max_age.min(cache_max_age);
        let expires_at = Instant::now() + ttl;
        if let Ok(mut guard) = cache.lock() {
            guard.insert(
                did.clone(),
                CachedEntry::Live {
                    document: document.clone(),
                    expires_at,
                },
            );
        }
        Ok(document)
    }

    /// Resolve a trust-root DID with the shorter
    /// [`MAX_TRUST_ROOT_CACHE_AGE`] cache (§7.3 / §7.4).
    ///
    /// Used by trust-declaration verification. Distinct cache
    /// from `resolve()`'s per-request cache; `invalidate(did)`
    /// removes from both.
    ///
    /// # Errors
    ///
    /// Same as `resolve()`.
    pub async fn resolve_for_trust_root(
        &self,
        did: &Did,
        deadline: Instant,
        trace_id: TraceId,
    ) -> Result<DidDocument, DidResolutionError> {
        self.resolve_with_cache(
            did,
            deadline,
            trace_id,
            &self.trust_root_cache,
            self.config.max_trust_root_cache_age,
        )
        .await
    }

    fn emit_rotation_audit(
        &self,
        did: &Did,
        previous: &DidDocument,
        current: &DidDocument,
        trace_id: TraceId,
    ) {
        let Some(sink) = &self.audit_sink else { return };
        let event = SubstrateAuditEvent::DidDocumentRotated {
            trace_id,
            did: did.clone(),
            previous_methods: previous
                .verification_methods
                .iter()
                .map(|(k, _)| *k)
                .collect(),
            current_methods: current
                .verification_methods
                .iter()
                .map(|(k, _)| *k)
                .collect(),
            at: SystemTime::now(),
        };
        let _ = sink.record(event);
    }

    fn emit_invalidation_audit(
        &self,
        did: &Did,
        source: crate::audit::InvalidationSource,
        trace_id: TraceId,
    ) {
        let Some(sink) = &self.audit_sink else { return };
        let event = SubstrateAuditEvent::DidDocumentInvalidated {
            trace_id,
            did: did.clone(),
            invalidated_by: source,
            at: SystemTime::now(),
        };
        let _ = sink.record(event);
    }
}

#[async_trait]
impl<F: HttpDidFetcher> DidResolver for DefaultDidResolver<F> {
    async fn resolve(
        &self,
        did: &Did,
        deadline: Instant,
        trace_id: TraceId,
    ) -> Result<DidDocument, DidResolutionError> {
        self.resolve_with_cache(
            did,
            deadline,
            trace_id,
            &self.document_cache,
            self.config.max_document_cache_age,
        )
        .await
    }

    async fn invalidate(&self, did: &Did, trace_id: TraceId) {
        let removed_doc = self
            .document_cache
            .lock()
            .ok()
            .and_then(|mut g| g.remove(did));
        let removed_trust = self
            .trust_root_cache
            .lock()
            .ok()
            .and_then(|mut g| g.remove(did));
        if removed_doc.is_some() || removed_trust.is_some() {
            self.emit_invalidation_audit(
                did,
                crate::audit::InvalidationSource::Operator,
                trace_id,
            );
        }
    }

    fn supported_methods(&self) -> &[&'static str] {
        &["plc", "web"]
    }
}

/// Extract the DID method (the second `:`-separated component).
/// Returns `"unknown"` for malformed DIDs (the resolver surfaces
/// these as `MethodNotSupported`).
fn did_method(did: &Did) -> &str {
    let s = did.as_str();
    let mut iter = s.split(':');
    iter.next(); // "did"
    iter.next().unwrap_or("unknown")
}

/// Parse a [`RawDidDoc`] into a [`DidDocument`]. The W3C DID spec
/// commits a JSON shape; Phase 4c implements the common-subset
/// parser that handles `did:plc` and `did:web` documents in
/// ATProto convention.
fn parse_did_document(
    did: &Did,
    raw: &RawDidDoc,
) -> Result<DidDocument, DidResolutionError> {
    let json: serde_json::Value = serde_json::from_slice(&raw.bytes)
        .map_err(|_| DidResolutionError::Malformed)?;

    // verificationMethod array.
    let mut verification_methods = Vec::new();
    if let Some(arr) = json.get("verificationMethod").and_then(|v| v.as_array()) {
        for entry in arr {
            // ATProto convention: verificationMethod entries carry
            // an `id` URI fragment, a `controller` DID, and either
            // `publicKeyMultibase` or `publicKeyJwk`. For Phase 4c
            // we accept the multibase form (proto-blue's existing
            // shape) and synthesize a KeyId by hashing the public-
            // key bytes — chainlink for Phase 6 spec polish on the
            // KeyId-derivation rule.
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or(DidResolutionError::Malformed)?;
            let key_bytes = decode_multibase_key(entry).ok_or(DidResolutionError::Malformed)?;
            // Synthesize a KeyId from the id-fragment suffix where
            // possible; otherwise from a Blake3-equivalent stand-
            // in. For Phase 4c we use the first 32 bytes of a
            // SHA-2-style mixing of the key bytes by zero-padding
            // — this is a placeholder until §7.3's KeyId derivation
            // rule is committed in spec polish.
            let key_id = synthesize_key_id(id, &key_bytes);
            verification_methods.push((
                key_id,
                PublicKey {
                    algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                    bytes: key_bytes,
                },
            ));
        }
    }

    // services array.
    let mut services = Vec::new();
    if let Some(arr) = json.get("service").and_then(|v| v.as_array()) {
        for entry in arr {
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let service_type = entry
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let endpoint = entry
                .get("serviceEndpoint")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            services.push(DidService {
                id,
                service_type,
                endpoint,
            });
        }
    }

    // alsoKnownAs array.
    let mut also_known_as = Vec::new();
    if let Some(arr) = json.get("alsoKnownAs").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(s) = entry.as_str() {
                also_known_as.push(s.to_string());
            }
        }
    }

    Ok(DidDocument {
        did: did.clone(),
        verification_methods,
        rotation_history: Vec::new(),
        services,
        also_known_as,
        resolved_at: SystemTime::now(),
        // Default per-document TTL; downstream cache caps at
        // MAX_DID_DOCUMENT_CACHE_AGE.
        resolver_cache_max_age: MAX_DID_DOCUMENT_CACHE_AGE,
    })
}

/// Decode the `publicKeyMultibase` value from a verification-
/// method entry. Phase 4c handles the `z`-prefixed base58btc
/// form ATProto uses; other multibase variants surface as `None`
/// → `Malformed`.
fn decode_multibase_key(entry: &serde_json::Value) -> Option<[u8; 32]> {
    let mb = entry.get("publicKeyMultibase").and_then(|v| v.as_str())?;
    if !mb.starts_with('z') {
        return None;
    }
    // Strip the `z` prefix; the remainder is base58btc.
    let payload = &mb[1..];
    // Phase 4c uses a minimal base58btc decoder rather than
    // pulling in another crypto crate. The payload encodes the
    // public-key bytes with a 2-byte multicodec prefix
    // (0xed 0x01 for Ed25519). Strip the prefix and accept the
    // 32 bytes that follow.
    let decoded = base58btc_decode(payload)?;
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..]);
    Some(key)
}

const BASE58_ALPHABET: &[u8] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58btc_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = vec![0u8; s.len()];
    let mut len = 0usize;
    for c in s.bytes() {
        let mut carry = BASE58_ALPHABET.iter().position(|&a| a == c)? as u32;
        for byte in &mut out[..len] {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out[len] = (carry & 0xff) as u8;
            len += 1;
            carry >>= 8;
        }
    }
    // Leading zeros in the input encode leading zero bytes.
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut result = vec![0u8; zeros];
    out[..len].reverse();
    result.extend_from_slice(&out[..len]);
    Some(result)
}

/// Synthesize a [`KeyId`] for a verification method. ATProto
/// convention for the `KeyId` derivation rule isn't fully
/// committed in §7.3; Phase 4c uses the suffix of the
/// verification-method id (the part after `#`) padded/hashed to
/// 32 bytes via a deterministic mixing scheme. Chainlink for
/// Phase 6 polish.
fn synthesize_key_id(id_uri: &str, key_bytes: &[u8; 32]) -> KeyId {
    // Take the suffix after '#' (e.g., `#atproto`).
    let suffix = id_uri.rsplit('#').next().unwrap_or(id_uri);
    let mut out = [0u8; 32];
    let suffix_bytes = suffix.as_bytes();
    // Mix: first 16 bytes from the suffix (zero-padded); next 16
    // from the key bytes' first 16. Deterministic and
    // round-tripable for tests.
    for (i, b) in suffix_bytes.iter().take(16).enumerate() {
        out[i] = *b;
    }
    out[16..].copy_from_slice(&key_bytes[..16]);
    KeyId::from_bytes(out)
}

/// Federation-peer kind (§7.7 round-4 reshape: distinct
/// `Internal` vs `Federation` peers).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerKind {
    /// Substrate-internal peer: operator-owned, full-trust
    /// baseline.
    Internal,
    /// External federation peer: operator-managed trust per
    /// declaration.
    Federation,
}

/// Per-peer health snapshot (§7.7 round-4: mandatory
/// `peer_health`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHealth {
    /// Whether the peer is currently considered reachable.
    pub reachable: bool,
    /// When the resolver last observed activity from this peer.
    pub last_observed_at: std::time::SystemTime,
    /// Operator-visible health notes. Bounded length (§7.5
    /// round-5 patch bound `PeerHealth.operator_notes`); Phase 4
    /// enforces the cap.
    pub operator_notes: String,
}

/// Trust query for a specific cross-peer operation (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TrustQuery {
    /// The peer DID being queried about.
    pub peer: Did,
    /// What operation is being attempted.
    pub operation: TrustOperation,
}

/// What cross-peer operation a [`TrustQuery`] is about (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustOperation {
    /// Accept a sync-channel handshake from this peer.
    AcceptSyncHandshake,
    /// Accept a capability claim issued by this peer.
    AcceptCapabilityClaim,
    /// Replicate a record from this peer.
    ReplicateRecord,
}

/// Trust resolver decision (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustDecision {
    /// Accept the operation.
    Accept,
    /// Reject the operation.
    Reject,
}

/// Federation-peer trust resolver (§7.7).
///
/// Operator-managed; the crate provides the trait surface, not
/// the policy.
#[async_trait]
pub trait PeerTrustResolver: Send + Sync {
    /// Decide whether to trust `query`. Honors `deadline` against
    /// any upstream lookups.
    async fn trust_for_operation(
        &self,
        query: &TrustQuery,
        deadline: Instant,
    ) -> Result<TrustDecision, PeerTrustError>;

    /// Record an observation about a peer's behavior; the
    /// resolver may incorporate it into future decisions.
    async fn record_peer_observation(
        &self,
        peer: &Did,
        observation: PeerObservation,
        deadline: Instant,
    ) -> Result<(), PeerTrustError>;

    /// Current health snapshot for a peer.
    async fn peer_health(
        &self,
        peer: &Did,
        deadline: Instant,
    ) -> Result<PeerHealth, PeerTrustError>;
}

/// Peer-behavior observation submitted to a
/// [`PeerTrustResolver`] (§7.7).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum PeerObservation {
    /// Peer signature verified successfully.
    SignatureVerified,
    /// Peer signature failed verification.
    SignatureFailed,
    /// Peer was unreachable for a sync attempt.
    Unreachable,
    /// Peer answered within the operation's deadline.
    ResponseWithin(Duration),
}

/// Peer-trust resolver failure (§7.7).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PeerTrustError {
    /// Peer is not configured in the operator's trust set.
    #[error("peer is not configured")]
    UnknownPeer,
    /// Operation exceeded the supplied deadline.
    #[error("peer-trust query exceeded deadline")]
    DeadlineExceeded,
    /// Upstream lookup failed.
    #[error("peer-trust upstream error: {0}")]
    UpstreamError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SignatureAlgorithm;

    fn sample_did() -> Did {
        Did::new("did:plc:resolverexample").unwrap()
    }

    fn sample_pubkey(byte: u8) -> PublicKey {
        PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: [byte; 32],
        }
    }

    fn sample_doc(did: &Did, key_byte: u8) -> DidDocument {
        DidDocument {
            did: did.clone(),
            verification_methods: vec![(KeyId::from_bytes([key_byte; 32]), sample_pubkey(key_byte))],
            rotation_history: vec![],
            services: vec![],
            also_known_as: vec![],
            resolved_at: SystemTime::now(),
            resolver_cache_max_age: Duration::from_secs(3600),
        }
    }

    /// Mock fetcher backed by an in-memory map. Each call counter
    /// records how many times the fetcher was actually invoked
    /// (so we can verify cache hits don't re-fetch).
    struct MockFetcher {
        responses: Mutex<HashMap<Did, Result<RawDidDoc, DidResolutionError>>>,
        plc_calls: Mutex<u32>,
        web_calls: Mutex<u32>,
    }

    impl MockFetcher {
        fn new() -> Self {
            MockFetcher {
                responses: Mutex::new(HashMap::new()),
                plc_calls: Mutex::new(0),
                web_calls: Mutex::new(0),
            }
        }

        fn set(&self, did: &Did, response: Result<RawDidDoc, DidResolutionError>) {
            self.responses.lock().unwrap().insert(did.clone(), response);
        }
    }

    #[async_trait]
    impl HttpDidFetcher for MockFetcher {
        async fn fetch_plc(
            &self,
            did: &Did,
            _deadline: Instant,
        ) -> Result<RawDidDoc, DidResolutionError> {
            *self.plc_calls.lock().unwrap() += 1;
            self.responses
                .lock()
                .unwrap()
                .get(did)
                .cloned()
                .unwrap_or(Err(DidResolutionError::NotFound))
        }
        async fn fetch_web(
            &self,
            did: &Did,
            _deadline: Instant,
        ) -> Result<RawDidDoc, DidResolutionError> {
            *self.web_calls.lock().unwrap() += 1;
            self.responses
                .lock()
                .unwrap()
                .get(did)
                .cloned()
                .unwrap_or(Err(DidResolutionError::NotFound))
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn test_trace_id() -> TraceId {
        TraceId::from_bytes([0xAB; 16])
    }

    /// §7.3 ceilings pinned.
    #[test]
    fn cache_age_constants_pinned_per_7_3() {
        assert_eq!(MAX_DID_DOCUMENT_CACHE_AGE, Duration::from_secs(3600));
        assert_eq!(MAX_TRUST_ROOT_CACHE_AGE, Duration::from_secs(60));
    }

    #[test]
    fn resolver_config_defaults_match_7_3() {
        let c = ResolverConfig::default();
        assert_eq!(c.max_document_cache_age, MAX_DID_DOCUMENT_CACHE_AGE);
        assert_eq!(c.max_trust_root_cache_age, MAX_TRUST_ROOT_CACHE_AGE);
        assert_eq!(c.plc_directory_url, "https://plc.directory");
    }

    #[test]
    fn resolver_supported_methods_default_is_plc_and_web() {
        // Provided via the trait's default impl when impls don't
        // override.
        struct BareImpl;
        #[async_trait]
        impl DidResolver for BareImpl {
            async fn resolve(
                &self,
                _did: &Did,
                _deadline: Instant,
                _trace_id: TraceId,
            ) -> Result<DidDocument, DidResolutionError> {
                unimplemented!()
            }
            async fn invalidate(&self, _did: &Did, _trace_id: TraceId) {}
        }
        let r = BareImpl;
        assert_eq!(r.supported_methods(), &["plc", "web"]);
    }

    /// Build a minimal valid did:plc-style JSON document with a
    /// single Ed25519 verification method via the
    /// publicKeyMultibase scheme our parser accepts.
    fn build_did_plc_json(_did: &Did, key_bytes: &[u8; 32]) -> Vec<u8> {
        // multibase z-base58btc encoding of [0xed, 0x01,
        // <32 key bytes>] = 34-byte payload.
        let mut payload = vec![0xed, 0x01];
        payload.extend_from_slice(key_bytes);
        let mb = format!("z{}", base58btc_encode(&payload));
        let body = format!(
            r##"{{"verificationMethod":[{{"id":"#atproto","controller":"did:plc:x","publicKeyMultibase":"{mb}"}}]}}"##
        );
        body.into_bytes()
    }

    fn base58btc_encode(input: &[u8]) -> String {
        // Minimal encoder for the test fixture.
        let mut result = String::new();
        let mut leading_zeros = 0;
        for &b in input {
            if b == 0 {
                leading_zeros += 1;
            } else {
                break;
            }
        }
        let mut num = input.iter().fold(num_bigint_minimal::Big::zero(), |acc, &b| {
            acc.mul_u32(256).add_u32(b as u32)
        });
        while !num.is_zero() {
            let rem = num.div_mod_u32(58);
            result.push(BASE58_ALPHABET[rem as usize] as char);
        }
        for _ in 0..leading_zeros {
            result.push('1');
        }
        result.chars().rev().collect()
    }

    /// Trivial big-integer helper for the test base58 encoder
    /// (avoids pulling num_bigint as a dev-dep). Big-endian byte
    /// representation; supports mul-add and div-mod by u32.
    mod num_bigint_minimal {
        #[derive(Clone)]
        pub struct Big(pub Vec<u32>); // little-endian limbs
        impl Big {
            pub fn zero() -> Self {
                Big(vec![])
            }
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|&x| x == 0)
            }
            pub fn mul_u32(mut self, v: u32) -> Self {
                let mut carry: u64 = 0;
                for limb in &mut self.0 {
                    let p = (*limb as u64) * (v as u64) + carry;
                    *limb = (p & 0xffff_ffff) as u32;
                    carry = p >> 32;
                }
                while carry > 0 {
                    self.0.push((carry & 0xffff_ffff) as u32);
                    carry >>= 32;
                }
                self
            }
            pub fn add_u32(mut self, v: u32) -> Self {
                let mut carry = v as u64;
                for limb in &mut self.0 {
                    let s = (*limb as u64) + carry;
                    *limb = (s & 0xffff_ffff) as u32;
                    carry = s >> 32;
                }
                if carry > 0 {
                    self.0.push(carry as u32);
                }
                self
            }
            pub fn div_mod_u32(&mut self, v: u32) -> u32 {
                let mut rem: u64 = 0;
                for i in (0..self.0.len()).rev() {
                    let acc = (rem << 32) | (self.0[i] as u64);
                    self.0[i] = (acc / (v as u64)) as u32;
                    rem = acc % (v as u64);
                }
                while let Some(&0) = self.0.last() {
                    self.0.pop();
                }
                rem as u32
            }
        }
    }

    #[tokio::test]
    async fn resolve_caches_fresh_documents() {
        let fetcher = MockFetcher::new();
        let did = sample_did();
        let key_bytes = [7u8; 32];
        fetcher.set(
            &did,
            Ok(RawDidDoc {
                bytes: build_did_plc_json(&did, &key_bytes),
                content_type: ContentType::ApplicationJson,
            }),
        );
        let resolver = DefaultDidResolver::new(fetcher);
        // First resolve hits the fetcher.
        let _doc1 = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap();
        // Second resolve hits the cache; fetcher call count
        // remains at 1.
        let _doc2 = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap();
        let calls = *resolver.fetcher.plc_calls.lock().unwrap();
        assert_eq!(calls, 1, "expected one fetch, got {calls}");
    }

    #[tokio::test]
    async fn invalidate_clears_cache_and_forces_refetch() {
        let fetcher = MockFetcher::new();
        let did = sample_did();
        let key_bytes = [7u8; 32];
        fetcher.set(
            &did,
            Ok(RawDidDoc {
                bytes: build_did_plc_json(&did, &key_bytes),
                content_type: ContentType::ApplicationJson,
            }),
        );
        let resolver = DefaultDidResolver::new(fetcher);
        let _doc1 = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap();
        resolver.invalidate(&did, test_trace_id()).await;
        // After invalidation the next resolve fetches fresh.
        let _doc2 = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap();
        let calls = *resolver.fetcher.plc_calls.lock().unwrap();
        assert_eq!(calls, 2, "expected two fetches after invalidation, got {calls}");
    }

    #[tokio::test]
    async fn tombstoned_did_caches_tombstone_permanently() {
        let fetcher = MockFetcher::new();
        let did = sample_did();
        fetcher.set(&did, Err(DidResolutionError::Tombstoned));
        let resolver = DefaultDidResolver::new(fetcher);
        let err1 = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap_err();
        let err2 = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap_err();
        assert!(matches!(err1, DidResolutionError::Tombstoned));
        assert!(matches!(err2, DidResolutionError::Tombstoned));
        // Only the first fetch triggers a network call; the
        // second hits the cached tombstone.
        let calls = *resolver.fetcher.plc_calls.lock().unwrap();
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn two_caches_isolate_per_request_and_trust_root() {
        let fetcher = MockFetcher::new();
        let did = sample_did();
        let key_bytes = [7u8; 32];
        fetcher.set(
            &did,
            Ok(RawDidDoc {
                bytes: build_did_plc_json(&did, &key_bytes),
                content_type: ContentType::ApplicationJson,
            }),
        );
        let resolver = DefaultDidResolver::new(fetcher);
        // Per-request cache fetches once.
        let _doc_a = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap();
        // Trust-root cache is a separate code path; it fetches
        // independently of the per-request cache.
        let _doc_b = resolver.resolve_for_trust_root(&did, deadline(), test_trace_id()).await.unwrap();
        let calls = *resolver.fetcher.plc_calls.lock().unwrap();
        assert_eq!(calls, 2, "expected two fetches across two caches, got {calls}");
        // Per-request cache hit: third call to resolve doesn't
        // touch the fetcher.
        let _doc_c = resolver.resolve(&did, deadline(), test_trace_id()).await.unwrap();
        // Trust-root cache hit: third call to resolve_for_trust_root
        // doesn't touch the fetcher either.
        let _doc_d = resolver.resolve_for_trust_root(&did, deadline(), test_trace_id()).await.unwrap();
        let calls_after = *resolver.fetcher.plc_calls.lock().unwrap();
        assert_eq!(calls_after, 2, "both caches should hit; got {calls_after}");
    }

    #[tokio::test]
    async fn unsupported_method_returns_method_not_supported() {
        let fetcher = MockFetcher::new();
        let resolver = DefaultDidResolver::new(fetcher);
        let weird_did = Did::new("did:weird:something").unwrap();
        let err = resolver.resolve(&weird_did, deadline(), test_trace_id()).await.unwrap_err();
        assert!(matches!(err, DidResolutionError::MethodNotSupported(_)));
    }

    /// Smoke-test for the in-tree base58btc decoder by round-
    /// tripping a small payload through encode/decode.
    #[test]
    fn base58btc_round_trip() {
        let payload = vec![0xed, 0x01, 1, 2, 3, 4, 5];
        let encoded = base58btc_encode(&payload);
        let decoded = base58btc_decode(&encoded).unwrap();
        assert_eq!(payload, decoded);
    }

    /// The synthesize_key_id helper produces deterministic
    /// 32-byte ids from the (id-uri, key-bytes) pair. Same
    /// inputs → same output; different ids → different outputs.
    #[test]
    fn synthesize_key_id_is_deterministic() {
        let id1 = synthesize_key_id("did:plc:x#atproto", &[7; 32]);
        let id2 = synthesize_key_id("did:plc:x#atproto", &[7; 32]);
        let id3 = synthesize_key_id("did:plc:x#different", &[7; 32]);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    /// Sanity: parse_did_document accepts a minimal multibase-
    /// encoded document.
    #[test]
    fn parse_did_document_accepts_multibase_did_plc() {
        let did = sample_did();
        let key = [9u8; 32];
        let raw = RawDidDoc {
            bytes: build_did_plc_json(&did, &key),
            content_type: ContentType::ApplicationJson,
        };
        let doc = parse_did_document(&did, &raw).unwrap();
        assert_eq!(doc.did, did);
        assert_eq!(doc.verification_methods.len(), 1);
        assert_eq!(doc.verification_methods[0].1.bytes, key);
    }

    /// Sample-doc fixture is unused here but pinned so the
    /// compiler doesn't drop the test infrastructure if a
    /// resolver test that uses it is later removed.
    #[test]
    fn sample_doc_helper_constructs_expected_shape() {
        let did = sample_did();
        let doc = sample_doc(&did, 5);
        assert_eq!(doc.did, did);
        assert_eq!(doc.verification_methods.len(), 1);
    }
}
