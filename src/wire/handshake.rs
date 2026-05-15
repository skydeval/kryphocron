// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §7.5 sync-channel handshake protocol — message types,
//! canonical CBOR encoders, signature build/verify helpers, and
//! the keyed-Blake3 [`derive_session_id`] construction.
//!
//! The three-message handshake (`Hello → Response → Established`)
//! establishes a session between two substrate peers. §7.5 commits
//! the message shapes verbatim; this module implements the
//! deterministic CBOR encoding for the sign-input of each message
//! and the wire-envelope encoding for transmission. Receive-side
//! decoding and the orchestrating `verify_sync_handshake` live in
//! [`crate::verification`] (Phase 4d follow-up commit).
//!
//! # Domain separation discipline
//!
//! Every signature in the handshake covers the canonical CBOR of
//! the message with all signature fields excluded, prefixed by a
//! per-message domain tag. The four tags are:
//!
//! - [`HELLO_DOMAIN_TAG`] — initiator-signed Hello.
//! - [`ACCEPT_DOMAIN_TAG`] — responder-signed Accept.
//! - [`REJECT_DOMAIN_TAG`] — responder-signed Reject.
//! - [`ESTABLISHED_DOMAIN_TAG`] — initiator-signed Established.
//!
//! §7.5 commits the `reject/` and `established/` tags verbatim
//! (lines 6558 and 6831). The `hello/` and `accept/` tags split a
//! family-prefix that §7.5's signing-canonicalization paragraph
//! describes ambiguously ("`b\"kryphocron/v1/sync-handshake/\"`
//! for Hello / Response, plus the established-specific prefix
//! above"). Phase 4d takes the conservative reading — per-message
//! suffixes — to mirror the explicitly-distinct `reject/` and
//! `established/` tags. A Phase 6 spec patch will pin this
//! decision in the design doc directly.
//!
//! # W6 receive-side capability-class discipline
//!
//! The handshake itself does not carry capability claims; that
//! exchange is post-handshake (`KryphocronClaim`-scheme messages
//! over the established session). The receiver-side §7.6 verifier
//! still applies the W6 belt-and-suspenders rejection of substrate-
//! and moderation-class capabilities — Phase 4d does not change
//! that path.

use std::time::{Duration, SystemTime};

use ciborium::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use smallvec::SmallVec;

use kryphocron_lexicons::SemVer;

use crate::audit::BatchRejectionReason;
use crate::identity::{
    PublicKey, ServiceIdentity, SessionId, SignatureAlgorithm, SubstrateSessionDerivationKey,
};
use crate::proto::{Did, Nsid};
use crate::wire::canonical_cbor;
use crate::wire::signature::ClaimSignature;

// ============================================================
// §7.5 — domain separation tags.
// ============================================================

/// Domain separation tag for the initiator-signed Hello payload.
pub const HELLO_DOMAIN_TAG: &[u8] = b"kryphocron/v1/sync-handshake/hello/";

/// Domain separation tag for the responder-signed Accept payload.
pub const ACCEPT_DOMAIN_TAG: &[u8] = b"kryphocron/v1/sync-handshake/accept/";

/// Domain separation tag for the responder-signed Reject payload.
/// §7.5-committed verbatim (line 6558).
pub const REJECT_DOMAIN_TAG: &[u8] = b"kryphocron/v1/sync-handshake/reject/";

/// Domain separation tag for the initiator-signed Established
/// payload. §7.5-committed verbatim (line 6831).
pub const ESTABLISHED_DOMAIN_TAG: &[u8] =
    b"kryphocron/v1/sync-handshake/established/";

// ============================================================
// §7.5 — federation peer time-window default.
// ============================================================

/// Default time-window ceiling the responder applies when a
/// federation-peer initiator's `requested_scope.time_window` is
/// `None` (§7.5 line 6620).
///
/// 7 days. `PeerKind::Internal` peers are exempt from this
/// ceiling — substrate-internal components configured under
/// `PeerKind::Internal` may request `time_window: None` without
/// operator-policy override; the substrate-class trust context
/// already establishes mutual trust at the operator-deployment
/// level. Federation peers requesting `None` get narrowed to
/// `Some(TimeWindow { start: now - DEFAULT_FEDERATION_TIME_WINDOW, end: now })`
/// unless explicit `PeerTrustConstraints.max_sync_scope` overrides.
pub const DEFAULT_FEDERATION_TIME_WINDOW: Duration =
    Duration::from_secs(7 * 86400);

// ============================================================
// §7.5 — handshake-only primitive types.
// ============================================================

/// 32-byte initiator-chosen session nonce (§7.5).
///
/// Initiators MUST generate a fresh nonce per handshake from the
/// OS CSPRNG. The nonce is the per-handshake input the responder
/// mixes with `responder_entropy` to derive the session id (see
/// [`derive_session_id`]). Replays of the same nonce by the same
/// initiator are detected by the handshake nonce tracker (Phase
/// 4d follow-up commit) and rejected with
/// [`crate::audit::BatchRejectionReason::HandshakeNonceReplay`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionNonce([u8; 32]);

impl SessionNonce {
    /// Construct from raw bytes. Operators with HSM-managed RNG
    /// supply nonces via this path.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        SessionNonce(bytes)
    }

    /// Generate from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG must be available");
        SessionNonce(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Direction of records the initiator wants to exchange (§7.5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDirection {
    /// Initiator wants to receive records from the responder.
    Receive,
    /// Initiator wants to send records to the responder.
    Send,
    /// Both directions.
    Bidirectional,
}

impl SyncDirection {
    fn wire_name(self) -> &'static str {
        match self {
            SyncDirection::Receive => "receive",
            SyncDirection::Send => "send",
            SyncDirection::Bidirectional => "bidirectional",
        }
    }

    fn from_wire(name: &str) -> Option<Self> {
        match name {
            "receive" => Some(SyncDirection::Receive),
            "send" => Some(SyncDirection::Send),
            "bidirectional" => Some(SyncDirection::Bidirectional),
            _ => None,
        }
    }
}

/// Inclusive-start, exclusive-end time window for sync-channel
/// scope (§7.5).
///
/// Intentionally distinct from [`crate::authority::TimeWindow`]:
/// the authority-side window is constructor-validated against
/// scope-error semantics meant for capability scopes; the
/// handshake's window is a peer-supplied bound that tolerates
/// equal start/end (degenerate empty windows are still
/// canonically encodable). The verifier rejects inverted windows
/// at the §7.5 entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncTimeWindow {
    /// Inclusive lower bound.
    pub start: SystemTime,
    /// Exclusive upper bound.
    pub end: SystemTime,
}

/// Initiator-requested or responder-narrowed sync scope (§7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequestedScope {
    /// Which lexicon NSIDs the initiator wants. Empty == "all
    /// kryphocron NSIDs".
    pub nsids: SmallVec<[Nsid; 8]>,
    /// Optional time window. `None` == "from beginning of time"
    /// for internal peers; federation peers get narrowed to a
    /// 7-day window per [`DEFAULT_FEDERATION_TIME_WINDOW`].
    pub time_window: Option<SyncTimeWindow>,
    /// Direction of records to exchange.
    pub direction: SyncDirection,
}

// ============================================================
// §7.5 — Hello / Accept / Reject / Established message types.
// ============================================================

/// Initiator-sent Hello (first message of the §7.5 handshake).
#[derive(Debug, Clone)]
pub struct SyncChannelHello {
    /// Initiator's substrate identity.
    pub initiator_identity: ServiceIdentity,
    /// Initiator's lexicon-set version.
    pub initiator_lexicon_set_version: SemVer,
    /// Per-handshake initiator nonce.
    pub proposed_session_nonce: SessionNonce,
    /// Initiator's requested scope.
    pub requested_scope: SyncRequestedScope,
    /// Signature by the initiator over the canonical CBOR of the
    /// fields above plus `at`, prefixed with [`HELLO_DOMAIN_TAG`].
    pub initiator_signature: ClaimSignature,
    /// Wallclock at construction.
    pub at: SystemTime,
}

/// Responder-sent Accept (second message, success branch).
#[derive(Debug, Clone)]
pub struct SyncChannelAccept {
    /// Responder's substrate identity.
    pub responder_identity: ServiceIdentity,
    /// Responder's lexicon-set version.
    pub responder_lexicon_set_version: SemVer,
    /// Session id derived via [`derive_session_id`] from the
    /// initiator's nonce and the responder's per-handshake entropy.
    pub session_id: SessionId,
    /// The responder-narrowed scope. Equal to or narrower than the
    /// initiator's requested scope.
    pub negotiated_scope: SyncRequestedScope,
    /// Signature by the responder over the canonical CBOR of the
    /// fields above plus `at`, prefixed with [`ACCEPT_DOMAIN_TAG`].
    pub responder_signature: ClaimSignature,
    /// Wallclock at construction.
    pub at: SystemTime,
}

/// Responder-sent Reject (second message, rejection branch).
#[derive(Debug, Clone)]
pub struct SyncChannelReject {
    /// Why the responder rejected the Hello.
    pub reason: BatchRejectionReason,
    /// Responder's substrate identity. Always present even on
    /// rejection per §7.5 — initiators must verify the rejection
    /// signature against this identity, and rejections from an
    /// unknown responder are discarded as no-message-received.
    pub responder_identity: ServiceIdentity,
    /// Signature by the responder over the canonical CBOR of the
    /// fields above plus `at`, prefixed with [`REJECT_DOMAIN_TAG`].
    pub responder_signature: ClaimSignature,
    /// Wallclock at construction.
    pub at: SystemTime,
}

/// Responder's reply to a Hello (§7.5).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SyncChannelResponse {
    /// Handshake accepted.
    Accept(SyncChannelAccept),
    /// Handshake rejected.
    Reject(SyncChannelReject),
}

/// Initiator-sent Established (third message; binds session).
///
/// The initiator signs the canonical CBOR of
/// `(session_id, responder_identity, at)` prefixed with
/// [`ESTABLISHED_DOMAIN_TAG`]. The `responder_identity` is NOT
/// carried in the on-wire Established struct because the responder
/// (the verifier) knows its own identity; verification reconstructs
/// the sign-input from the session-bound state.
#[derive(Debug, Clone)]
pub struct SyncChannelEstablished {
    /// Session id from the prior Accept message.
    pub session_id: SessionId,
    /// Initiator's signature over
    /// `(session_id, responder_identity, at)` under
    /// [`ESTABLISHED_DOMAIN_TAG`].
    pub initiator_signature: ClaimSignature,
    /// Wallclock at construction.
    pub at: SystemTime,
}

// ============================================================
// §7.5 — derive_session_id keyed-Blake3 construction.
// ============================================================

/// Compute a [`SessionId`] from `(proposed_session_nonce,
/// responder_entropy)` keyed under
/// [`SubstrateSessionDerivationKey`] (§7.5 line 6670-6689).
///
/// Construction:
///
/// ```text
/// session_id = blake3::keyed_hash(
///     key   = SubstrateSessionDerivationKey,
///     input = proposed_session_nonce || responder_entropy,
/// )
/// ```
///
/// `proposed_session_nonce` is 32 bytes from the initiator's
/// `SyncChannelHello`; `responder_entropy` is 32 bytes the
/// responder generates fresh per handshake. Output is the 32-byte
/// `SessionId`.
///
/// Properties (§7.5 line 6691-6705):
///
/// - The responder is committed to a unique session id at Accept
///   time via its signature over the Accept message.
/// - Distinct (nonce, entropy) pairs produce distinct session ids
///   (Blake3 keyed-hash collision resistance).
/// - Cross-substrate session-id predictability is foreclosed by
///   the per-instance keying: an attacker observing session ids
///   from one substrate instance cannot predict ids from another.
///
/// Property NOT provided (§7.5 line 6706-6714): the initiator
/// cannot verify the responder ran the construction honestly. The
/// session id itself does not carry session-authentication
/// properties; authentication rests on the signatures over Hello,
/// Accept, and Established.
#[must_use]
pub fn derive_session_id(
    key: &SubstrateSessionDerivationKey,
    proposed_nonce: &SessionNonce,
    responder_entropy: &[u8; 32],
) -> SessionId {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(proposed_nonce.as_bytes());
    input[32..].copy_from_slice(responder_entropy);
    let hash = blake3::keyed_hash(key.as_bytes(), &input);
    SessionId::from_bytes(*hash.as_bytes())
}

// ============================================================
// §7.5 — sign-input encoders + signature build/verify helpers.
// ============================================================

/// Maximum on-wire size of any single handshake message (§7.5).
///
/// Conservative bound: each message contains at most one
/// `SyncRequestedScope` carrying up to 8 NSIDs (each at most 256
/// bytes) plus identity / signature material. 8 KiB has substantial
/// headroom and bounds responder-side memory while parsing.
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 8 * 1024;

/// Hello sign-input: canonical CBOR of all fields except the
/// signature, prefixed with [`HELLO_DOMAIN_TAG`].
#[must_use]
pub fn hello_sign_input(
    initiator: &ServiceIdentity,
    initiator_lexicon_set_version: SemVer,
    proposed_session_nonce: &SessionNonce,
    requested_scope: &SyncRequestedScope,
    at: SystemTime,
) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("initiator_identity".into()),
            service_identity_value(initiator),
        ),
        (
            Value::Text("initiator_lexicon_set_version".into()),
            semver_value(initiator_lexicon_set_version),
        ),
        (
            Value::Text("proposed_session_nonce".into()),
            Value::Bytes(proposed_session_nonce.as_bytes().to_vec()),
        ),
        (
            Value::Text("requested_scope".into()),
            sync_requested_scope_value(requested_scope),
        ),
        (Value::Text("at".into()), system_time_value(at)),
    ]);
    let mut out = HELLO_DOMAIN_TAG.to_vec();
    out.extend_from_slice(&canonical_cbor::to_canonical_bytes(payload));
    out
}

/// Accept sign-input: canonical CBOR of all fields except the
/// signature, prefixed with [`ACCEPT_DOMAIN_TAG`].
#[must_use]
pub fn accept_sign_input(
    responder: &ServiceIdentity,
    responder_lexicon_set_version: SemVer,
    session_id: &SessionId,
    negotiated_scope: &SyncRequestedScope,
    at: SystemTime,
) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("responder_identity".into()),
            service_identity_value(responder),
        ),
        (
            Value::Text("responder_lexicon_set_version".into()),
            semver_value(responder_lexicon_set_version),
        ),
        (
            Value::Text("session_id".into()),
            Value::Bytes(session_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("negotiated_scope".into()),
            sync_requested_scope_value(negotiated_scope),
        ),
        (Value::Text("at".into()), system_time_value(at)),
    ]);
    let mut out = ACCEPT_DOMAIN_TAG.to_vec();
    out.extend_from_slice(&canonical_cbor::to_canonical_bytes(payload));
    out
}

/// Reject sign-input: canonical CBOR of all fields except the
/// signature, prefixed with [`REJECT_DOMAIN_TAG`].
#[must_use]
pub fn reject_sign_input(
    reason: &BatchRejectionReason,
    responder: &ServiceIdentity,
    at: SystemTime,
) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("reason".into()),
            batch_rejection_reason_value(reason),
        ),
        (
            Value::Text("responder_identity".into()),
            service_identity_value(responder),
        ),
        (Value::Text("at".into()), system_time_value(at)),
    ]);
    let mut out = REJECT_DOMAIN_TAG.to_vec();
    out.extend_from_slice(&canonical_cbor::to_canonical_bytes(payload));
    out
}

/// Established sign-input: canonical CBOR of
/// `(session_id, responder_identity, at)` prefixed with
/// [`ESTABLISHED_DOMAIN_TAG`].
///
/// The verifier (responder) reconstructs this from
/// `(message.session_id, self.responder_identity, message.at)` —
/// `responder_identity` is not carried on the wire because the
/// session-bound responder always knows its own identity.
#[must_use]
pub fn established_sign_input(
    session_id: &SessionId,
    responder: &ServiceIdentity,
    at: SystemTime,
) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("session_id".into()),
            Value::Bytes(session_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("responder_identity".into()),
            service_identity_value(responder),
        ),
        (Value::Text("at".into()), system_time_value(at)),
    ]);
    let mut out = ESTABLISHED_DOMAIN_TAG.to_vec();
    out.extend_from_slice(&canonical_cbor::to_canonical_bytes(payload));
    out
}

/// Sign a sign-input under an Ed25519 signing key, producing a
/// [`ClaimSignature`].
///
/// All four handshake messages use Ed25519 by construction — §7.2's
/// algorithm allowlist defaults to Ed25519 only, and §7.5 does not
/// commit additional algorithms for handshake signing.
#[must_use]
pub fn sign_handshake_payload(key: &SigningKey, sign_input: &[u8]) -> ClaimSignature {
    let sig = key.sign(sign_input);
    ClaimSignature {
        algorithm: SignatureAlgorithm::Ed25519,
        bytes: sig.to_bytes(),
    }
}

/// Verify a handshake-message signature against the signer's
/// public key.
///
/// Returns `true` on a valid signature, `false` on any verification
/// failure (bad signature, wrong algorithm). Callers translate to
/// the appropriate error variant in their domain.
#[must_use]
pub fn verify_handshake_signature(
    public_key: &PublicKey,
    sign_input: &[u8],
    signature: &ClaimSignature,
) -> bool {
    if signature.algorithm != SignatureAlgorithm::Ed25519
        || public_key.algorithm != SignatureAlgorithm::Ed25519
    {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&public_key.bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&signature.bytes);
    vk.verify(sign_input, &sig).is_ok()
}

// ============================================================
// CBOR helpers: shared encoding shapes for ServiceIdentity, SemVer,
// SyncRequestedScope, BatchRejectionReason, SystemTime.
//
// These mirror the helpers in `wire/claim.rs` deliberately — the
// duplication is cheap and keeps each wire-format module self-
// contained. A Phase 6 refactor may consolidate them into a shared
// `wire::serde_helpers` module if the duplication grows.
// ============================================================

fn service_identity_value(s: &ServiceIdentity) -> Value {
    Value::Map(vec![
        (
            Value::Text("did".into()),
            Value::Text(s.service_did().as_str().to_string()),
        ),
        (
            Value::Text("key_id".into()),
            Value::Bytes(s.key_id().as_bytes().to_vec()),
        ),
        (
            Value::Text("key_alg".into()),
            Value::Text(signature_alg_name(s.key_material().algorithm).into()),
        ),
        (
            Value::Text("key_material".into()),
            Value::Bytes(s.key_material().bytes.to_vec()),
        ),
    ])
}

fn signature_alg_name(a: SignatureAlgorithm) -> &'static str {
    match a {
        SignatureAlgorithm::Ed25519 => "Ed25519",
        SignatureAlgorithm::Es256 => "Es256",
        SignatureAlgorithm::Es256K => "Es256K",
    }
}

fn semver_value(v: SemVer) -> Value {
    Value::Array(vec![
        Value::Integer(v.major.into()),
        Value::Integer(v.minor.into()),
        Value::Integer(v.patch.into()),
    ])
}

fn sync_requested_scope_value(s: &SyncRequestedScope) -> Value {
    let nsids = Value::Array(
        s.nsids
            .iter()
            .map(|n| Value::Text(n.as_str().to_string()))
            .collect(),
    );
    let time_window = match s.time_window {
        None => Value::Null,
        Some(w) => Value::Map(vec![
            (Value::Text("start".into()), system_time_value(w.start)),
            (
                Value::Text("end".into()),
                system_time_value(w.end),
            ),
        ]),
    };
    Value::Map(vec![
        (Value::Text("nsids".into()), nsids),
        (Value::Text("time_window".into()), time_window),
        (
            Value::Text("direction".into()),
            Value::Text(s.direction.wire_name().to_string()),
        ),
    ])
}

fn batch_rejection_reason_value(r: &BatchRejectionReason) -> Value {
    match r {
        BatchRejectionReason::LexiconSetMajorVersionMismatch { local, peer } => {
            Value::Map(vec![
                (
                    Value::Text("kind".into()),
                    Value::Text("lexicon_set_major_version_mismatch".into()),
                ),
                (Value::Text("local".into()), semver_value(*local)),
                (Value::Text("peer".into()), semver_value(*peer)),
            ])
        }
        BatchRejectionReason::UnauthorizedPeer => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("unauthorized_peer".into()),
        )]),
        BatchRejectionReason::HandshakeSignatureInvalid => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("handshake_signature_invalid".into()),
        )]),
        BatchRejectionReason::HandshakeTimeout => Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("handshake_timeout".into()),
        )]),
        BatchRejectionReason::HandshakeNonceReplay { first_seen_at } => {
            Value::Map(vec![
                (
                    Value::Text("kind".into()),
                    Value::Text("handshake_nonce_replay".into()),
                ),
                (
                    Value::Text("first_seen_at".into()),
                    system_time_value(*first_seen_at),
                ),
            ])
        }
    }
}

/// Encode a [`SystemTime`] as a CBOR unsigned integer (Unix epoch
/// seconds). Mirrors the helper in `wire/claim.rs`; times before
/// the Unix epoch are not part of the crate's threat model.
fn system_time_value(t: SystemTime) -> Value {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH not supported")
        .as_secs();
    Value::Integer(secs.into())
}

// ============================================================
// Receive-side: full-wire decoders.
//
// Phase 4d's `verify_sync_handshake` (in `verification.rs`) calls
// these to round-trip on-wire bytes through canonical CBOR before
// signature verification. The non-canonical-input rejection
// pattern from Phase 4b applies symmetrically here.
// ============================================================

/// Decode the on-wire CBOR bytes of a `SyncChannelHello` into the
/// constituent fields plus the carried signature.
///
/// Returns `Err(())` for any structural problem; callers translate
/// to a verification-error variant.
#[allow(clippy::type_complexity)]
pub(crate) fn decode_hello_wire(
    bytes: &[u8],
) -> Result<
    (
        ServiceIdentity, // initiator_identity
        SemVer,          // initiator_lexicon_set_version
        SessionNonce,
        SyncRequestedScope,
        SystemTime, // at
        ClaimSignature,
    ),
    (),
> {
    let value = canonical_cbor::from_bytes(bytes)?;
    let map = into_map(&value)?;
    Ok((
        decode_service_identity(map_get(map, "initiator_identity")?)?,
        decode_semver(map_get(map, "initiator_lexicon_set_version")?)?,
        decode_session_nonce(map_get(map, "proposed_session_nonce")?)?,
        decode_sync_requested_scope(map_get(map, "requested_scope")?)?,
        decode_system_time(map_get(map, "at")?)?,
        decode_claim_signature(map_get(map, "initiator_signature")?)?,
    ))
}

/// Decode the on-wire CBOR bytes of a `SyncChannelAccept`.
#[allow(clippy::type_complexity)]
pub(crate) fn decode_accept_wire(
    bytes: &[u8],
) -> Result<
    (
        ServiceIdentity, // responder_identity
        SemVer,          // responder_lexicon_set_version
        SessionId,
        SyncRequestedScope,
        SystemTime,
        ClaimSignature,
    ),
    (),
> {
    let value = canonical_cbor::from_bytes(bytes)?;
    let map = into_map(&value)?;
    Ok((
        decode_service_identity(map_get(map, "responder_identity")?)?,
        decode_semver(map_get(map, "responder_lexicon_set_version")?)?,
        decode_session_id(map_get(map, "session_id")?)?,
        decode_sync_requested_scope(map_get(map, "negotiated_scope")?)?,
        decode_system_time(map_get(map, "at")?)?,
        decode_claim_signature(map_get(map, "responder_signature")?)?,
    ))
}

/// Decode the on-wire CBOR bytes of a `SyncChannelReject`.
pub(crate) fn decode_reject_wire(
    bytes: &[u8],
) -> Result<
    (
        BatchRejectionReason,
        ServiceIdentity, // responder_identity
        SystemTime,
        ClaimSignature,
    ),
    (),
> {
    let value = canonical_cbor::from_bytes(bytes)?;
    let map = into_map(&value)?;
    Ok((
        decode_batch_rejection_reason(map_get(map, "reason")?)?,
        decode_service_identity(map_get(map, "responder_identity")?)?,
        decode_system_time(map_get(map, "at")?)?,
        decode_claim_signature(map_get(map, "responder_signature")?)?,
    ))
}

/// Decode the on-wire CBOR bytes of a `SyncChannelEstablished`.
pub(crate) fn decode_established_wire(
    bytes: &[u8],
) -> Result<(SessionId, SystemTime, ClaimSignature), ()> {
    let value = canonical_cbor::from_bytes(bytes)?;
    let map = into_map(&value)?;
    Ok((
        decode_session_id(map_get(map, "session_id")?)?,
        decode_system_time(map_get(map, "at")?)?,
        decode_claim_signature(map_get(map, "initiator_signature")?)?,
    ))
}

/// Re-encode a Hello to canonical bytes for the round-trip
/// canonicality check at receive-time.
#[must_use]
pub(crate) fn hello_to_wire_bytes(h: &SyncChannelHello) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("initiator_identity".into()),
            service_identity_value(&h.initiator_identity),
        ),
        (
            Value::Text("initiator_lexicon_set_version".into()),
            semver_value(h.initiator_lexicon_set_version),
        ),
        (
            Value::Text("proposed_session_nonce".into()),
            Value::Bytes(h.proposed_session_nonce.as_bytes().to_vec()),
        ),
        (
            Value::Text("requested_scope".into()),
            sync_requested_scope_value(&h.requested_scope),
        ),
        (Value::Text("at".into()), system_time_value(h.at)),
        (
            Value::Text("initiator_signature".into()),
            claim_signature_value(&h.initiator_signature),
        ),
    ]);
    canonical_cbor::to_canonical_bytes(payload)
}

/// Re-encode an Accept to canonical bytes.
#[must_use]
pub(crate) fn accept_to_wire_bytes(a: &SyncChannelAccept) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("responder_identity".into()),
            service_identity_value(&a.responder_identity),
        ),
        (
            Value::Text("responder_lexicon_set_version".into()),
            semver_value(a.responder_lexicon_set_version),
        ),
        (
            Value::Text("session_id".into()),
            Value::Bytes(a.session_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("negotiated_scope".into()),
            sync_requested_scope_value(&a.negotiated_scope),
        ),
        (Value::Text("at".into()), system_time_value(a.at)),
        (
            Value::Text("responder_signature".into()),
            claim_signature_value(&a.responder_signature),
        ),
    ]);
    canonical_cbor::to_canonical_bytes(payload)
}

/// Re-encode a Reject to canonical bytes.
#[must_use]
pub(crate) fn reject_to_wire_bytes(r: &SyncChannelReject) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("reason".into()),
            batch_rejection_reason_value(&r.reason),
        ),
        (
            Value::Text("responder_identity".into()),
            service_identity_value(&r.responder_identity),
        ),
        (Value::Text("at".into()), system_time_value(r.at)),
        (
            Value::Text("responder_signature".into()),
            claim_signature_value(&r.responder_signature),
        ),
    ]);
    canonical_cbor::to_canonical_bytes(payload)
}

/// Re-encode an Established to canonical bytes.
#[must_use]
pub(crate) fn established_to_wire_bytes(e: &SyncChannelEstablished) -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("session_id".into()),
            Value::Bytes(e.session_id.as_bytes().to_vec()),
        ),
        (Value::Text("at".into()), system_time_value(e.at)),
        (
            Value::Text("initiator_signature".into()),
            claim_signature_value(&e.initiator_signature),
        ),
    ]);
    canonical_cbor::to_canonical_bytes(payload)
}

fn claim_signature_value(s: &ClaimSignature) -> Value {
    Value::Map(vec![
        (
            Value::Text("alg".into()),
            Value::Text(signature_alg_name(s.algorithm).into()),
        ),
        (
            Value::Text("bytes".into()),
            Value::Bytes(s.bytes.to_vec()),
        ),
    ])
}

// ============================================================
// Receive-side decoders: small, mechanical CBOR walkers.
// ============================================================

fn into_map(v: &Value) -> Result<&Vec<(Value, Value)>, ()> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(()),
    }
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a Value, ()> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s.as_str() == key))
        .map(|(_, v)| v)
        .ok_or(())
}

fn decode_service_identity(v: &Value) -> Result<ServiceIdentity, ()> {
    let m = into_map(v)?;
    let did = match map_get(m, "did")? {
        Value::Text(s) => Did::new(s).map_err(|_| ())?,
        _ => return Err(()),
    };
    let key_id_bytes: [u8; 32] = match map_get(m, "key_id")? {
        Value::Bytes(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        }
        _ => return Err(()),
    };
    let alg = match map_get(m, "key_alg")? {
        Value::Text(s) => decode_signature_alg(s)?,
        _ => return Err(()),
    };
    let key_material_bytes: [u8; 32] = match map_get(m, "key_material")? {
        Value::Bytes(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        }
        _ => return Err(()),
    };
    Ok(ServiceIdentity::new_internal(
        did,
        crate::identity::KeyId::from_bytes(key_id_bytes),
        PublicKey {
            algorithm: alg,
            bytes: key_material_bytes,
        },
        None,
    ))
}

fn decode_signature_alg(s: &str) -> Result<SignatureAlgorithm, ()> {
    match s {
        "Ed25519" => Ok(SignatureAlgorithm::Ed25519),
        "Es256" => Ok(SignatureAlgorithm::Es256),
        "Es256K" => Ok(SignatureAlgorithm::Es256K),
        _ => Err(()),
    }
}

fn decode_semver(v: &Value) -> Result<SemVer, ()> {
    let arr = match v {
        Value::Array(a) if a.len() == 3 => a,
        _ => return Err(()),
    };
    let major = decode_u32(&arr[0])?;
    let minor = decode_u32(&arr[1])?;
    let patch = decode_u32(&arr[2])?;
    Ok(SemVer::new(major, minor, patch))
}

fn decode_u32(v: &Value) -> Result<u32, ()> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            u32::try_from(n).map_err(|_| ())
        }
        _ => Err(()),
    }
}

fn decode_session_nonce(v: &Value) -> Result<SessionNonce, ()> {
    match v {
        Value::Bytes(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Ok(SessionNonce::from_bytes(a))
        }
        _ => Err(()),
    }
}

fn decode_session_id(v: &Value) -> Result<SessionId, ()> {
    match v {
        Value::Bytes(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Ok(SessionId::from_bytes(a))
        }
        _ => Err(()),
    }
}

fn decode_sync_requested_scope(v: &Value) -> Result<SyncRequestedScope, ()> {
    let m = into_map(v)?;
    let nsids = match map_get(m, "nsids")? {
        Value::Array(items) => {
            let mut sv: SmallVec<[Nsid; 8]> = SmallVec::new();
            for item in items {
                let s = match item {
                    Value::Text(s) => s,
                    _ => return Err(()),
                };
                sv.push(Nsid::new(s).map_err(|_| ())?);
            }
            sv
        }
        _ => return Err(()),
    };
    let time_window = match map_get(m, "time_window")? {
        Value::Null => None,
        Value::Map(_) => Some(decode_sync_time_window(map_get(m, "time_window")?)?),
        _ => return Err(()),
    };
    let direction = match map_get(m, "direction")? {
        Value::Text(s) => SyncDirection::from_wire(s).ok_or(())?,
        _ => return Err(()),
    };
    Ok(SyncRequestedScope {
        nsids,
        time_window,
        direction,
    })
}

fn decode_sync_time_window(v: &Value) -> Result<SyncTimeWindow, ()> {
    let m = into_map(v)?;
    let start = decode_system_time(map_get(m, "start")?)?;
    let end = decode_system_time(map_get(m, "end")?)?;
    Ok(SyncTimeWindow { start, end })
}

fn decode_system_time(v: &Value) -> Result<SystemTime, ()> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            let secs = u64::try_from(n).map_err(|_| ())?;
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        }
        _ => Err(()),
    }
}

fn decode_claim_signature(v: &Value) -> Result<ClaimSignature, ()> {
    let m = into_map(v)?;
    let alg = match map_get(m, "alg")? {
        Value::Text(s) => decode_signature_alg(s)?,
        _ => return Err(()),
    };
    let bytes: [u8; 64] = match map_get(m, "bytes")? {
        Value::Bytes(b) if b.len() == 64 => {
            let mut a = [0u8; 64];
            a.copy_from_slice(b);
            a
        }
        _ => return Err(()),
    };
    Ok(ClaimSignature {
        algorithm: alg,
        bytes,
    })
}

fn decode_batch_rejection_reason(v: &Value) -> Result<BatchRejectionReason, ()> {
    let m = into_map(v)?;
    let kind = match map_get(m, "kind")? {
        Value::Text(s) => s.as_str(),
        _ => return Err(()),
    };
    match kind {
        "lexicon_set_major_version_mismatch" => {
            let local = decode_semver(map_get(m, "local")?)?;
            let peer = decode_semver(map_get(m, "peer")?)?;
            Ok(BatchRejectionReason::LexiconSetMajorVersionMismatch {
                local,
                peer,
            })
        }
        "unauthorized_peer" => Ok(BatchRejectionReason::UnauthorizedPeer),
        "handshake_signature_invalid" => {
            Ok(BatchRejectionReason::HandshakeSignatureInvalid)
        }
        "handshake_timeout" => Ok(BatchRejectionReason::HandshakeTimeout),
        "handshake_nonce_replay" => {
            let first_seen_at =
                decode_system_time(map_get(m, "first_seen_at")?)?;
            Ok(BatchRejectionReason::HandshakeNonceReplay { first_seen_at })
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::KeyId;

    fn sample_identity(seed: u8) -> ServiceIdentity {
        let did = format!("did:plc:{seed:02x}sample0000000000");
        ServiceIdentity::new_internal(
            Did::new(&did).unwrap(),
            KeyId::from_bytes([seed; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [seed.wrapping_add(1); 32],
            },
            None,
        )
    }

    fn signing_pair(seed: u8) -> (SigningKey, PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        let pk = PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: vk.to_bytes(),
        };
        (sk, pk)
    }

    fn empty_scope() -> SyncRequestedScope {
        SyncRequestedScope {
            nsids: SmallVec::new(),
            time_window: None,
            direction: SyncDirection::Bidirectional,
        }
    }

    /// §7.5 derive_session_id: same inputs produce the same id;
    /// different inputs produce different ids.
    #[test]
    fn derive_session_id_is_deterministic_and_input_separated() {
        let key = SubstrateSessionDerivationKey::from_bytes([0x55; 32]);
        let nonce = SessionNonce::from_bytes([0x11; 32]);
        let entropy = [0x22; 32];

        let s1 = derive_session_id(&key, &nonce, &entropy);
        let s2 = derive_session_id(&key, &nonce, &entropy);
        assert_eq!(s1, s2, "deterministic for the same inputs");

        let other_entropy = [0x33; 32];
        let s3 = derive_session_id(&key, &nonce, &other_entropy);
        assert_ne!(s1, s3, "different entropy produces different session id");

        let other_nonce = SessionNonce::from_bytes([0x44; 32]);
        let s4 = derive_session_id(&key, &other_nonce, &entropy);
        assert_ne!(s1, s4, "different nonce produces different session id");
    }

    /// Cross-substrate predictability foreclosed: same (nonce,
    /// entropy) under different keys yields different session ids.
    #[test]
    fn derive_session_id_separates_by_substrate_key() {
        let key_a = SubstrateSessionDerivationKey::from_bytes([0xAA; 32]);
        let key_b = SubstrateSessionDerivationKey::from_bytes([0xBB; 32]);
        let nonce = SessionNonce::from_bytes([0x11; 32]);
        let entropy = [0x22; 32];

        let s_a = derive_session_id(&key_a, &nonce, &entropy);
        let s_b = derive_session_id(&key_b, &nonce, &entropy);
        assert_ne!(s_a, s_b);
    }

    /// Hello sign-input round-trips: signing then verifying with
    /// the matching public key succeeds.
    #[test]
    fn hello_sign_verify_round_trip() {
        let (sk, pk) = signing_pair(0x01);
        let mut id = sample_identity(0x01);
        // Patch the identity's key material to match the signing
        // key so verify_handshake_signature (which uses
        // PublicKey from arg) lines up with the test's intent.
        id = ServiceIdentity::new_internal(
            id.service_did().clone(),
            id.key_id(),
            pk,
            None,
        );
        let nonce = SessionNonce::from_bytes([0x42; 32]);
        let scope = empty_scope();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let input = hello_sign_input(&id, SemVer::new(1, 0, 0), &nonce, &scope, at);
        let sig = sign_handshake_payload(&sk, &input);
        assert!(verify_handshake_signature(id.key_material(), &input, &sig));
    }

    /// W8 separation: a Hello sign-input signature does NOT verify
    /// as an Accept sign-input signature even with otherwise
    /// identical fields.
    #[test]
    fn hello_signature_does_not_verify_as_accept() {
        let (sk, pk) = signing_pair(0x02);
        let id = ServiceIdentity::new_internal(
            Did::new("did:plc:samplesamplesample0000").unwrap(),
            KeyId::from_bytes([0x02; 32]),
            pk,
            None,
        );
        let nonce = SessionNonce::from_bytes([0x42; 32]);
        let scope = empty_scope();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        // Sign as Hello.
        let hello_input =
            hello_sign_input(&id, SemVer::new(1, 0, 0), &nonce, &scope, at);
        let sig = sign_handshake_payload(&sk, &hello_input);

        // Cross-verify against Accept input. The Accept input has
        // a different domain tag and different field layout — both
        // independently sufficient to make verification fail.
        let session_id = SessionId::from_bytes([0xFF; 32]);
        let accept_input = accept_sign_input(
            &id,
            SemVer::new(1, 0, 0),
            &session_id,
            &scope,
            at,
        );
        assert!(!verify_handshake_signature(id.key_material(), &accept_input, &sig));
    }

    /// W8 separation: the four domain tags are byte-distinct.
    #[test]
    fn handshake_domain_tags_are_byte_distinct() {
        let tags = [
            HELLO_DOMAIN_TAG,
            ACCEPT_DOMAIN_TAG,
            REJECT_DOMAIN_TAG,
            ESTABLISHED_DOMAIN_TAG,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(
                    tags[i], tags[j],
                    "handshake domain tags must be byte-distinct"
                );
            }
        }
    }

    /// W8 separation across §7 contexts: handshake tags are
    /// distinct from the §7.6 capability-claim tag and the §7.4
    /// trust-declaration tag. The §4.8 attribution-receipt tag
    /// has no constant in Phase 4d (Phase 1 ships receipts as
    /// type-shape only; the constant lands when receipts are
    /// wired); the literal is checked against the documented
    /// value here directly.
    #[test]
    fn handshake_domain_tags_are_distinct_from_other_section_tags() {
        let handshake_tags: [&[u8]; 4] = [
            HELLO_DOMAIN_TAG,
            ACCEPT_DOMAIN_TAG,
            REJECT_DOMAIN_TAG,
            ESTABLISHED_DOMAIN_TAG,
        ];
        let other_tags: [&[u8]; 3] = [
            crate::wire::CLAIM_DOMAIN_TAG,
            crate::trust::TRUST_DECLARATION_DOMAIN_TAG,
            b"kryphocron/v1/attribution-receipt/",
        ];
        for h in handshake_tags {
            for o in other_tags {
                assert_ne!(
                    h, o,
                    "handshake tag must be distinct from other §7 tags"
                );
            }
        }
    }

    /// Hello wire round-trip: encoded bytes decode back to the
    /// same fields, and re-encoding produces byte-identical output
    /// (canonicality property).
    #[test]
    fn hello_wire_round_trips_canonical() {
        let (sk, pk) = signing_pair(0x05);
        let id = ServiceIdentity::new_internal(
            Did::new("did:plc:samplesamplesample0000").unwrap(),
            KeyId::from_bytes([0x05; 32]),
            pk,
            None,
        );
        let nonce = SessionNonce::from_bytes([0x42; 32]);
        let scope = empty_scope();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let input = hello_sign_input(&id, SemVer::new(1, 0, 0), &nonce, &scope, at);
        let sig = sign_handshake_payload(&sk, &input);
        let hello = SyncChannelHello {
            initiator_identity: id.clone(),
            initiator_lexicon_set_version: SemVer::new(1, 0, 0),
            proposed_session_nonce: nonce,
            requested_scope: scope.clone(),
            initiator_signature: sig,
            at,
        };
        let bytes = hello_to_wire_bytes(&hello);
        let (
            d_id,
            d_ver,
            d_nonce,
            d_scope,
            d_at,
            d_sig,
        ) = decode_hello_wire(&bytes).unwrap();
        assert_eq!(d_id, id);
        assert_eq!(d_ver, SemVer::new(1, 0, 0));
        assert_eq!(d_nonce, nonce);
        assert_eq!(d_scope, scope);
        assert_eq!(d_at, at);
        assert_eq!(d_sig, hello.initiator_signature);

        // Canonicality: re-encode and compare byte-for-byte.
        let re_encoded = canonical_cbor::to_canonical_bytes(
            canonical_cbor::from_bytes(&bytes).unwrap(),
        );
        assert_eq!(bytes, re_encoded);
    }

    /// `MAX_HANDSHAKE_MESSAGE_SIZE` pinned at 8 KiB.
    #[test]
    fn max_handshake_message_size_pinned() {
        assert_eq!(MAX_HANDSHAKE_MESSAGE_SIZE, 8 * 1024);
    }

    /// `DEFAULT_FEDERATION_TIME_WINDOW` pinned at 7 days per §7.5.
    #[test]
    fn default_federation_time_window_pinned_at_7_days() {
        assert_eq!(DEFAULT_FEDERATION_TIME_WINDOW, Duration::from_secs(7 * 86400));
    }
}
