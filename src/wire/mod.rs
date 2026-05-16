// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.8 wire-level capability claims, attribution chains, and
//! delegation-receipt machinery.
//!
//! v0.1 ships the **type vocabulary** plus the deterministic
//! CBOR serialization, signature verification, and rotation-history
//! resolution committed by §7.
//!
//! The wire types are surfaced at the crate root via `pub use`
//! so consumers refer to them without traversing the `wire`
//! submodule path; §9.1's committed public modules do not include
//! `wire` as a separate module, but the types it ships are part
//! of the public API surface.

mod canonical_cbor;
mod claim;
mod handshake;
mod handshake_tracker;
mod nonce;
mod receipt;
mod signature;
mod tracker;

pub use self::claim::{
    CapabilityClaim, ClaimConstructionError, ClaimOrigin, ResourceScope, ScopeVariantName,
    MAX_CAPABILITY_CLAIM_SIZE, MAX_CLAIM_VALIDITY,
};

// Crate-internal re-exports for the `verification` submodule —
// the §7.6 receive-side path needs the wire-envelope decoder,
// the round-trip canonicality check, and the domain tag for
// signature verification. None of these surface publicly.
pub(crate) use self::claim::{
    decode_wire as decode_wire_envelope,
    wire_bytes_are_canonical as wire_envelope_is_canonical, CLAIM_DOMAIN_TAG,
};

// Crate-internal re-exports for the `trust` submodule (§7.4).
// The canonical-CBOR helpers are reused for trust-declaration
// encode / decode + canonicality check.
pub(crate) use self::canonical_cbor::{
    from_bytes as canonical_cbor_decode, to_canonical_bytes as canonical_cbor_encode,
};
pub use self::nonce::{
    ClaimNonce, JwtNonce, NonceFreshness, NonceIssuerKey, NonceKind, NoncePrincipal,
    NonceTracker, NonceTrackerError,
};
pub use self::tracker::{
    DefaultNonceTracker, DEFAULT_NONCE_RETENTION, DEFAULT_PER_PARTITION_CAP,
};
pub use self::receipt::{
    sign_delegation_receipt, AttributionChainWire, AttributionEntryWire,
    AttributionPrincipal, DelegationReceipt, DelegationReceiptPayload,
    ReceiptVerificationFailure,
};

// Crate-internal: chain walker reaches into receipt.rs for the
// payload canonicalization + signature-verify helpers. The
// `delegation_receipt_payload_canonical_bytes` and
// `ATTRIBUTION_RECEIPT_DOMAIN_TAG` re-exports stay declared so
// future submodules can pull them through the crate-internal
// namespace; current usage is via the `verify_delegation_receipt`
// helper which encapsulates both.
#[allow(unused_imports)]
pub(crate) use self::receipt::{
    delegation_receipt_payload_canonical_bytes, verify_delegation_receipt,
    ATTRIBUTION_RECEIPT_DOMAIN_TAG,
};
pub use self::signature::ClaimSignature;

// §7.5 sync-handshake protocol surface.
pub use self::handshake::{
    accept_sign_input, derive_session_id, established_sign_input, hello_sign_input,
    reject_sign_input, sign_handshake_payload, verify_handshake_signature,
    SessionNonce, SyncChannelAccept, SyncChannelEstablished, SyncChannelHello,
    SyncChannelReject, SyncChannelResponse, SyncDirection, SyncRequestedScope,
    SyncTimeWindow, ACCEPT_DOMAIN_TAG, DEFAULT_FEDERATION_TIME_WINDOW,
    ESTABLISHED_DOMAIN_TAG, HELLO_DOMAIN_TAG, MAX_HANDSHAKE_MESSAGE_SIZE,
    REJECT_DOMAIN_TAG,
};
pub use self::handshake_tracker::{
    DefaultHandshakeNonceTracker, HandshakeNonceTracker,
    MAX_HANDSHAKE_NONCE_REPLAY_WINDOW, MAX_HANDSHAKE_NONCE_TRACKER_ENTRIES,
};

// Crate-internal re-exports for `verification`: receive-side
// decoders + canonicality re-encoders used by
// `verify_sync_handshake`.
#[allow(unused_imports)]
pub(crate) use self::handshake::{
    accept_to_wire_bytes, decode_accept_wire, decode_established_wire,
    decode_hello_wire, decode_reject_wire, established_to_wire_bytes,
    hello_to_wire_bytes, reject_to_wire_bytes,
};

/// Maximum entries in an [`AttributionChainWire`] (§4.8). Matches
/// the in-process [`crate::ingress::MAX_CHAIN_DEPTH`].
pub const MAX_ROTATION_DEPTH: usize = crate::identity::MAX_ROTATION_DEPTH;
