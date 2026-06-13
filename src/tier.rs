// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.1 Tier model and §4.4 tier-aware envelope types.
//!
//! The tier system encodes a record's visibility class as a
//! type-level property. A function emitting to a public surface
//! takes `Tiered<T, PublicTier>`; passing in a
//! `Tiered<T, PrivateTier>` is a compile error, not a runtime
//! check.
//!
//! Crate split: the runtime [`Tier`] enum, [`Visibility`], and
//! [`UnknownNsid`] live in `kryphocron-lexicons` because the
//! build-script-generated `impl Tier { pub fn from_nsid }`
//! (§5.3) must sit in the same crate as `Tier` (Rust orphan
//! rules). The type-system witnesses ([`TierWitness`],
//! [`PublicTier`], [`PrivateTier`], [`HasNsid`], [`Tiered`],
//! [`MixedTier`]) stay here — they are the substrate's threat-
//! model vocabulary built on top of `Tier`, not part of the
//! lexicon set.
//!
//! The crate ships two tier witnesses in v1 — [`PublicTier`] and
//! [`PrivateTier`] — and the runtime [`Tier`] enum is
//! `#[non_exhaustive]` so future tier additions are additive.
//!
//! ## Why `Ord` is not derived
//!
//! [`Tier`] deliberately does **not** implement [`Ord`] /
//! [`PartialOrd`]. The reasons (§4.1):
//!
//! - **Lattice extensibility.** Future tiers may sit parallel to
//!   `Private` (e.g., a `Sensitive` tier for moderation
//!   workflows) rather than above or below it. A total order
//!   would freeze the lattice shape.
//! - **Wrong vocabulary.** Viewers don't have tiers; viewers have
//!   [`crate::AuthContext`]s with capabilities. Comparing a
//!   viewer's "level" against a record's tier is not the abstraction
//!   the substrate offers — the visibility predicate
//!   ([`visible_to`]) is.

use core::marker::PhantomData;

use crate::proto::Nsid;
use crate::sealed;

// Re-export the lexicon-companion-crate canonical types (§5.3:
// `Tier::from_nsid` must live in the same crate as `Tier`).
pub use kryphocron_lexicons::{Tier, UnknownNsid, Visibility};

/// Visibility predicate against an [`crate::AuthContext`] (§4.1).
///
/// Coarse tier × requester-class predicate. Returns one of three
/// [`Visibility`] variants:
///
/// - [`Visibility::Visible`] — viewer may read.
/// - [`Visibility::Hidden`] — viewer is audience-gated; the
///   record exists but is not visible to this viewer at the tier
///   layer.
/// - [`Visibility::Forbidden`] — policy-forbidden (e.g., blocked
///   relationship). Reserved for v0.2 oracle-aware enrichment;
///   not returned by the v0.1 implementation since visible_to has
///   no resource-owner DID to consult the block oracle against.
///
/// V0.1 matrix:
///
/// | Tier            | Anonymous | Did                | Service          |
/// | --------------- | --------- | ------------------ | ---------------- |
/// | [`Tier::Public`]  | Visible   | Visible            | Visible          |
/// | [`Tier::Private`] | Hidden    | Hidden (see below) | Visible (§4.6)   |
///
/// **Private + Did returns Hidden conservatively.** visible_to is
/// structurally tier-only — its signature `(tier, ctx)` carries
/// neither the value nor its audience field, so audience-membership
/// can't be consulted at this layer. Callers needing audience-aware
/// visibility on a specific record should call the bind path
/// directly (which consults the audience oracle at stage 3).
/// The conservative-Hidden default fails closed for the read
/// path; bind succeeds for in-audience viewers.
///
/// **Private + Service returns Visible** per §4.6
/// read-everything-authority — substrate-internal machinery
/// processes records regardless of tier; the tier discipline
/// exists for user-facing read paths.
///
/// `Hidden` and `Forbidden` are distinct **internally** — audit
/// pipelines and operators distinguish "exists but audience-gated
/// for this viewer" from "policy-forbidden" — but they collapse
/// to the same wire response (per §4.1's closed-namespace
/// non-enumeration discipline).
#[must_use]
pub fn visible_to(tier: Tier, ctx: &crate::ingress::AuthContext<'_>) -> Visibility {
    use crate::ingress::Requester;
    match (tier, ctx.requester()) {
        // Public: visible to everyone.
        (Tier::Public, _) => Visibility::Visible,
        // Private + Service: substrate-internal sees all (§4.6).
        (Tier::Private, Requester::Service(_)) => Visibility::Visible,
        // Private + Anonymous or Did: Hidden (conservative —
        // visible_to is tier-only; bind runs the real audience
        // check).
        (Tier::Private, _) => Visibility::Hidden,
        // Tier is #[non_exhaustive]; future variants fail closed.
        (_, _) => Visibility::Hidden,
    }
}

/// Trait carrying a [`Tier`] as a type-level constant.
///
/// Sealed. The crate ships [`PublicTier`] and [`PrivateTier`] in
/// v1; new tier witnesses ship alongside new [`Tier`] variants
/// in future versions.
pub trait TierWitness: sealed::Sealed + 'static {
    /// The runtime tier this witness represents.
    const TIER: Tier;
}

/// Public-tier witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicTier;

impl sealed::Sealed for PublicTier {}
impl TierWitness for PublicTier {
    const TIER: Tier = Tier::Public;
}

/// Private-tier witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrivateTier;

impl sealed::Sealed for PrivateTier {}
impl TierWitness for PrivateTier {
    const TIER: Tier = Tier::Private;
}

/// Trait connecting record types to their NSID and tier.
///
/// Sealed: only crate-generated record types (from the §5
/// codegen pipeline) implement [`HasNsid`]. Consumers cannot
/// declare arbitrary types as kryphocron records.
pub trait HasNsid: sealed::Sealed + 'static {
    /// The NSID identifying this record type.
    const NSID: &'static str;
    /// The tier this record type belongs to.
    type Tier: TierWitness;

    /// Convenience: produce a typed [`Nsid`] handle.
    fn nsid(&self) -> Nsid {
        Nsid::new(Self::NSID).expect("HasNsid::NSID must be a valid NSID literal")
    }
}

/// Tier-tagged envelope around a record type.
///
/// `Tiered<T, T::Tier>` is the only legal shape: [`Tiered::wrap`]
/// requires `T: HasNsid<Tier = Ti>`. A mismatch is a compile
/// error — the type system rejects `Tiered<PublicRecord, PrivateTier>`
/// because [`Tiered::wrap`] is unimplementable for that combination.
pub struct Tiered<T, Ti: TierWitness> {
    inner: T,
    _tier: PhantomData<Ti>,
    _private: PhantomData<sealed::Token>,
}

impl<T, Ti: TierWitness> Tiered<T, Ti>
where
    T: HasNsid<Tier = Ti>,
{
    /// Wrap a record value in its tier envelope.
    ///
    /// Infallible. The trait bound `T: HasNsid<Tier = Ti>`
    /// guarantees the wrapped tier matches the record type's
    /// declared tier.
    #[must_use]
    pub fn wrap(record: T) -> Self {
        Tiered {
            inner: record,
            _tier: PhantomData,
            _private: PhantomData,
        }
    }

    /// Borrow the wrapped record.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Consume the envelope, returning the wrapped record.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: core::fmt::Debug, Ti: TierWitness> core::fmt::Debug for Tiered<T, Ti> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tiered")
            .field("tier", &Ti::TIER)
            .field("inner", &self.inner)
            .finish()
    }
}

/// Envelope around a value that may be public-tier or private-
/// tier (§4.4 `MixedTier`).
///
/// Typically used in ingress code that hasn't yet branched on
/// tier classification.
#[non_exhaustive]
pub enum MixedTier<P, Q>
where
    P: HasNsid<Tier = PublicTier>,
    Q: HasNsid<Tier = PrivateTier>,
{
    /// Public-tier value.
    Public(Tiered<P, PublicTier>),
    /// Private-tier value.
    Private(Tiered<Q, PrivateTier>),
}

// §5.4 build-script-emitted `sealed::Sealed` + `HasNsid` impls for each
// kryphocron-lexicons record type, plus `KRYPHOCRON_IMPLEMENTED_NSIDS` and
// the §5.3 compile-time consistency assertion. Generated by `build.rs` from
// `KRYPHOCRON_LEXICON_REGISTRY`. Included here so the impls see the private
// `crate::sealed` seal and the local `HasNsid` / tier witnesses.
include!(concat!(env!("OUT_DIR"), "/has_nsid_impls.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_v1_variant_set_pinned() {
        // Pin the v1 variant set. From outside the defining crate
        // the compiler treats #[non_exhaustive] enums as
        // non-exhaustive, so this match still has to use a
        // wildcard; the assertion is that the two known variants
        // exist with the spec-committed shape.
        let t = Tier::Public;
        match t {
            Tier::Public | Tier::Private => {}
            _ => panic!("unexpected non-v1 Tier variant"),
        }
    }

    #[test]
    fn visibility_allows_read_only_visible() {
        assert!(Visibility::Visible.allows_read());
        assert!(!Visibility::Hidden.allows_read());
        assert!(!Visibility::Forbidden.allows_read());
    }

    #[test]
    fn tier_witnesses_carry_the_right_constants() {
        assert_eq!(PublicTier::TIER, Tier::Public);
        assert_eq!(PrivateTier::TIER, Tier::Private);
    }

    #[test]
    fn from_nsid_resolves_v1_lexicons() {
        // The eight v1 NSIDs resolve to the tiers committed by
        // §5.7 / §5.4.
        let cases: &[(&str, Tier)] = &[
            ("tools.kryphocron.feed.postPublic", Tier::Public),
            ("tools.kryphocron.feed.postPrivate", Tier::Private),
            ("tools.kryphocron.feed.like", Tier::Public),
            ("tools.kryphocron.feed.repost", Tier::Public),
            ("tools.kryphocron.feed.threadgate", Tier::Public),
            ("tools.kryphocron.graph.block", Tier::Private),
            ("tools.kryphocron.graph.mute", Tier::Private),
            ("tools.kryphocron.policy.audience", Tier::Private),
        ];
        for (nsid_str, expected_tier) in cases {
            let nsid = Nsid::new(nsid_str).unwrap();
            let resolved = Tier::from_nsid(&nsid).unwrap_or_else(|_| {
                panic!("registered NSID `{nsid_str}` did not resolve");
            });
            assert_eq!(resolved, *expected_tier, "{nsid_str}");
        }
    }

    #[test]
    fn from_nsid_unknown_returns_not_registered() {
        let nsid = Nsid::new("com.example.unknown.lexicon").unwrap();
        assert!(matches!(
            Tier::from_nsid(&nsid),
            Err(UnknownNsid::NotRegistered(_))
        ));
    }

    // ====================================================
    // visible_to tests.
    // ====================================================

    /// Minimal AuthContext fixture for the visible_to matrix tests.
    /// visible_to only consults `ctx.requester()`, so the sinks /
    /// oracles can be no-ops; we only vary the Requester variant.
    mod visible_to_fixture {
        use crate::audit::*;
        use crate::authority::moderation::InspectionNotificationQueueImpl;
        use crate::oracle::*;
        use std::time::{Duration, SystemTime};

        pub(super) struct NoSink;
        impl UserAuditSink for NoSink {
            fn record(&self, _: UserAuditEvent) -> Result<(), AuditError> {
                Ok(())
            }
        }
        impl ChannelAuditSink for NoSink {
            fn record(&self, _: ChannelAuditEvent) -> Result<(), AuditError> {
                Ok(())
            }
        }
        impl SubstrateAuditSink for NoSink {
            fn record(&self, _: SubstrateAuditEvent) -> Result<(), AuditError> {
                Ok(())
            }
        }
        impl ModerationAuditSink for NoSink {
            fn record(&self, _: ModerationAuditEvent) -> Result<(), AuditError> {
                Ok(())
            }
        }
        impl FallbackAuditSink for NoSink {
            fn record_panic(
                &self,
                _: SinkKind,
                _: crate::identity::TraceId,
                _: crate::authority::CapabilityKind,
                _: SystemTime,
            ) {
            }
            fn record_composite_failure(
                &self,
                _: crate::identity::TraceId,
                _: CompositeOpId,
                _: &[SinkKind],
                _: &[SinkKind],
                _: SystemTime,
            ) {
            }
            fn record_event(&self, _: FallbackAuditEvent) {}
        }
        impl InspectionNotificationQueueImpl for NoSink {
            fn enqueue(
                &self,
                _: &crate::proto::Did,
                _: crate::authority::InspectionNotification,
            ) {
            }
        }

        pub(super) struct NoOracle;
        impl BlockOracle for NoOracle {
            fn block_state(&self, _: &crate::proto::Did, _: &crate::proto::Did) -> BlockState {
                BlockState::None
            }
            fn last_synced_at(&self) -> SystemTime {
                SystemTime::UNIX_EPOCH
            }
            fn data_freshness_bound(&self) -> Duration {
                Duration::from_secs(60)
            }
            fn worst_case_latency_for(&self, _: BlockOracleQuery) -> Duration {
                Duration::ZERO
            }
        }
        impl AudienceOracle for NoOracle {
            fn audience_state(
                &self,
                _: &crate::proto::Did,
                _: &crate::authority::ResourceId,
            ) -> AudienceState {
                AudienceState::NoAudienceConfigured
            }
            fn last_synced_at(&self) -> SystemTime {
                SystemTime::UNIX_EPOCH
            }
            fn data_freshness_bound(&self) -> Duration {
                Duration::from_secs(60)
            }
            fn worst_case_latency_for(&self, _: AudienceOracleQuery) -> Duration {
                Duration::ZERO
            }
        }
        impl MuteOracle for NoOracle {
            fn mute_state(&self, _: &crate::proto::Did, _: &crate::proto::Did) -> MuteState {
                MuteState::None
            }
            fn last_synced_at(&self) -> SystemTime {
                SystemTime::UNIX_EPOCH
            }
            fn data_freshness_bound(&self) -> Duration {
                Duration::from_secs(60)
            }
            fn worst_case_latency_for(&self, _: MuteOracleQuery) -> Duration {
                Duration::ZERO
            }
        }
    }

    use crate::ingress::{
        AttributionChain, AuditSinks, AuthContext, OracleSet, Requester,
    };
    use crate::proto::Did;

    fn build_ctx<'a>(
        sink: &'a visible_to_fixture::NoSink,
        oracle: &'a visible_to_fixture::NoOracle,
        correlation_key: &'a crate::identity::CorrelationKey,
        requester: Requester,
    ) -> AuthContext<'a> {
        AuthContext::new_internal(
            requester,
            crate::identity::TraceId::from_bytes([0u8; 16]),
            AuditSinks {
                user: sink,
                channel: sink,
                substrate: sink,
                moderation: sink,
                fallback: sink,
                inspection_queue: sink,
                correlation_key,
            },
            OracleSet {
                block: oracle,
                audience: oracle,
                mute: oracle,
            },
            AttributionChain::empty(),
            crate::authority::capability::CapabilitySet::empty(),
        )
    }

    fn sample_did() -> Did {
        Did::new("did:plc:phase7e").unwrap()
    }

    /// §4.1 Public + Anonymous → Visible.
    #[test]
    fn public_visible_to_anonymous() {
        let sink = visible_to_fixture::NoSink;
        let oracle = visible_to_fixture::NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx(&sink, &oracle, &ck, Requester::Anonymous);
        assert_eq!(visible_to(Tier::Public, &ctx), Visibility::Visible);
    }

    /// §4.1 Public + Did → Visible.
    #[test]
    fn public_visible_to_did() {
        let sink = visible_to_fixture::NoSink;
        let oracle = visible_to_fixture::NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx(&sink, &oracle, &ck, Requester::Did(sample_did()));
        assert_eq!(visible_to(Tier::Public, &ctx), Visibility::Visible);
    }

    /// §4.1 Public + Service → Visible.
    #[test]
    fn public_visible_to_service() {
        let sink = visible_to_fixture::NoSink;
        let oracle = visible_to_fixture::NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc = crate::identity::ServiceIdentity::new_internal(
            sample_did(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        );
        let ctx = build_ctx(&sink, &oracle, &ck, Requester::Service(svc));
        assert_eq!(visible_to(Tier::Public, &ctx), Visibility::Visible);
    }

    /// §4.1 Private + Anonymous → Hidden (no identity to
    /// audience-check against).
    #[test]
    fn private_hidden_from_anonymous() {
        let sink = visible_to_fixture::NoSink;
        let oracle = visible_to_fixture::NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx(&sink, &oracle, &ck, Requester::Anonymous);
        assert_eq!(visible_to(Tier::Private, &ctx), Visibility::Hidden);
    }

    /// §4.1 Private + Did → Hidden (conservative; visible_to is
    /// tier-only and can't audience-check). Documented as the v0.1
    /// shape — bind path runs the real audience oracle at stage 3.
    #[test]
    fn private_hidden_from_did_conservative() {
        let sink = visible_to_fixture::NoSink;
        let oracle = visible_to_fixture::NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let ctx = build_ctx(&sink, &oracle, &ck, Requester::Did(sample_did()));
        assert_eq!(visible_to(Tier::Private, &ctx), Visibility::Hidden);
    }

    /// §4.1 / §4.6 Private + Service → Visible (substrate-internal
    /// sees all per read-everything-authority).
    #[test]
    fn private_visible_to_service() {
        let sink = visible_to_fixture::NoSink;
        let oracle = visible_to_fixture::NoOracle;
        let ck = crate::identity::CorrelationKey::from_bytes([0u8; 32]);
        let svc = crate::identity::ServiceIdentity::new_internal(
            sample_did(),
            crate::identity::KeyId::from_bytes([0u8; 32]),
            crate::identity::PublicKey {
                algorithm: crate::identity::SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        );
        let ctx = build_ctx(&sink, &oracle, &ck, Requester::Service(svc));
        assert_eq!(visible_to(Tier::Private, &ctx), Visibility::Visible);
    }
}
