//! Public-API integration tests.
//!
//! Runs as a separate compilation unit, so we see only what the
//! crate exposes publicly. Many wire-format types are
//! `#[non_exhaustive]` and cannot be struct-literal-constructed
//! from outside the crate — that is the intended behavior
//! (operator code receives them from verification paths, not
//! arbitrary construction). The field-shape pinning lives in the
//! crate's unit tests; this suite verifies what consumers *can*
//! depend on.
//!
//! Phase B verification points (Chrys-run) that this suite covers:
//!
//! - The closed-namespace capability vocabulary is visible and
//!   stable.
//! - Public-API type aliases and re-exports resolve.
//! - Trait-via-impl access to `MAX_AGE` and `KIND` constants
//!   on the v1 capability markers works as advertised.
//! - `BindError::AttributionReceiptInvalid` (§4.3 round-5 patch)
//!   is part of the public surface.
//! - `PeerKind` has the round-4 reshape variants distinct.

use std::time::Duration;

use kryphocron::{
    BindError, CapabilityClass, CapabilityKind, CapabilitySemantics, ReceiptVerificationFailure,
    Tier, UserCapability, Visibility, MAX_CHAIN_DEPTH,
};
use kryphocron::authority::{
    DeletePrivatePost, EditPrivatePost, ManageAudience, ModerationCapability, ModeratorRead,
    ModeratorRestore, ModeratorTakedown, ParticipatePrivate, ViewPrivate,
};
use kryphocron::resolver::PeerKind;

// ============================================================
// §4.1 tier model.
// ============================================================

#[test]
fn tier_has_public_and_private_variants() {
    let _public = Tier::Public;
    let _private = Tier::Private;
}

#[test]
fn visibility_three_variants() {
    let _v = Visibility::Visible;
    let _h = Visibility::Hidden;
    let _f = Visibility::Forbidden;
    assert!(Visibility::Visible.allows_read());
    assert!(!Visibility::Hidden.allows_read());
    assert!(!Visibility::Forbidden.allows_read());
}

// ============================================================
// §4.3 capability vocabulary and class partitioning.
// ============================================================

#[test]
fn capability_kind_v1_set_pinned() {
    let kinds = [
        CapabilityKind::ViewPrivate,
        CapabilityKind::ParticipatePrivate,
        CapabilityKind::EditPrivatePost,
        CapabilityKind::DeletePrivatePost,
        CapabilityKind::ManageAudience,
        CapabilityKind::EmitToSyncChannel,
        CapabilityKind::AppViewSync,
        CapabilityKind::GraphSync,
        CapabilityKind::ScanShard,
        CapabilityKind::ReplicatePrivate,
        CapabilityKind::GarbageCollect,
        CapabilityKind::ModeratorRead,
        CapabilityKind::ModeratorTakedown,
        CapabilityKind::ModeratorRestore,
    ];
    assert_eq!(kinds.len(), 14);
}

#[test]
fn user_class_capabilities_are_wire_eligible() {
    assert!(CapabilityKind::ViewPrivate.is_wire_eligible());
    assert!(CapabilityKind::EditPrivatePost.is_wire_eligible());
}

#[test]
fn substrate_and_moderation_never_wire_eligible() {
    for k in [
        CapabilityKind::ScanShard,
        CapabilityKind::ReplicatePrivate,
        CapabilityKind::GarbageCollect,
        CapabilityKind::ModeratorRead,
        CapabilityKind::ModeratorTakedown,
        CapabilityKind::ModeratorRestore,
    ] {
        assert!(!k.is_wire_eligible(), "{k:?} must not be wire-eligible");
    }
}

#[test]
fn capability_class_partitioning_consistent() {
    assert_eq!(CapabilityKind::ViewPrivate.class(), CapabilityClass::User);
    assert_eq!(
        CapabilityKind::EmitToSyncChannel.class(),
        CapabilityClass::Channel
    );
    assert_eq!(CapabilityKind::ScanShard.class(), CapabilityClass::Substrate);
    assert_eq!(
        CapabilityKind::ModeratorRead.class(),
        CapabilityClass::Moderation
    );
}

// ============================================================
// §4.7 proof lifetime upper bounds.
// ============================================================

#[test]
fn v1_max_age_table_matches_spec() {
    assert_eq!(<ViewPrivate as UserCapability>::MAX_AGE, Duration::from_secs(300));
    assert_eq!(
        <ParticipatePrivate as UserCapability>::MAX_AGE,
        Duration::from_secs(60)
    );
    assert_eq!(<EditPrivatePost as UserCapability>::MAX_AGE, Duration::from_secs(60));
    assert_eq!(
        <DeletePrivatePost as UserCapability>::MAX_AGE,
        Duration::from_secs(30)
    );
    assert_eq!(<ManageAudience as UserCapability>::MAX_AGE, Duration::from_secs(60));
    assert_eq!(
        <ModeratorRead as ModerationCapability>::MAX_AGE,
        Duration::from_secs(30)
    );
    assert_eq!(
        <ModeratorTakedown as ModerationCapability>::MAX_AGE,
        Duration::from_secs(10)
    );
    // ModeratorRestore is a Phase-1 interpretation (§4.7 spec
    // table didn't list it). See CHAINLINKS #6.
    assert_eq!(
        <ModeratorRestore as ModerationCapability>::MAX_AGE,
        Duration::from_secs(30)
    );
}

#[test]
fn v1_semantics_read_vs_write_pinned() {
    assert_eq!(
        <ViewPrivate as UserCapability>::SEMANTICS,
        CapabilitySemantics::Read
    );
    assert_eq!(
        <ParticipatePrivate as UserCapability>::SEMANTICS,
        CapabilitySemantics::Write
    );
    assert_eq!(
        <EditPrivatePost as UserCapability>::SEMANTICS,
        CapabilitySemantics::Write
    );
    assert_eq!(
        <DeletePrivatePost as UserCapability>::SEMANTICS,
        CapabilitySemantics::Write
    );
    assert_eq!(
        <ManageAudience as UserCapability>::SEMANTICS,
        CapabilitySemantics::Write
    );
}

// ============================================================
// §4.3 round-5 patch: BindError::AttributionReceiptInvalid.
// ============================================================

#[test]
fn bind_error_includes_attribution_receipt_invalid() {
    let e = BindError::AttributionReceiptInvalid {
        failing_hop: 3,
        reason: ReceiptVerificationFailure::Malformed,
    };
    match e {
        BindError::AttributionReceiptInvalid { failing_hop, .. } => {
            assert_eq!(failing_hop, 3);
        }
        _ => panic!("variant did not destructure as expected"),
    }
}

// ============================================================
// §7.7 round-4 reshape: PeerKind::{Internal, Federation}.
// ============================================================

#[test]
fn peer_kind_has_internal_and_federation() {
    let _i = PeerKind::Internal;
    let _f = PeerKind::Federation;
    assert_ne!(PeerKind::Internal, PeerKind::Federation);
}

// ============================================================
// §4.2 attribution chain bounds.
// ============================================================

#[test]
fn max_chain_depth_is_8() {
    assert_eq!(MAX_CHAIN_DEPTH, 8);
}
