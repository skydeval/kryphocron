//! §4.1 Tier model and §4.4 tier-aware envelope types.
//!
//! The tier system encodes a record's visibility class as a
//! type-level property. A function emitting to a public surface
//! takes `Tiered<T, PublicTier>`; passing in a
//! `Tiered<T, PrivateTier>` is a compile error, not a runtime
//! check.
//!
//! Phase 2 split: the runtime [`Tier`] enum, [`Visibility`], and
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

/// Visibility predicate against an [`crate::AuthContext`].
///
/// Free function form — `Tier` lives in `kryphocron-lexicons` so
/// the orphan rules prevent an inherent `impl Tier { fn visible_to
/// }` from this crate. Phase 4 may revisit by introducing an
/// extension trait. `Hidden` and `Forbidden` are distinct
/// **internally** — audit pipelines and operators distinguish
/// "exists but audience-gated for this viewer" from
/// "policy-forbidden" — but they collapse to the same wire response
/// (per §4.1's closed-namespace non-enumeration discipline).
#[must_use]
pub fn visible_to(_tier: Tier, _ctx: &crate::ingress::AuthContext<'_>) -> Visibility {
    // Phase 1/2: shape only. Phase 4 walks the §4.3 pipeline; the
    // public predicate result is one of three Visibility variants.
    unimplemented!("§4.1 visible_to: Phase 4 wires the pipeline");
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
/// codegen pipeline, Phase 2) implement [`HasNsid`]. Consumers
/// cannot declare arbitrary types as kryphocron records.
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
        // Phase 2 wires the registry. The eight v1 NSIDs resolve
        // to the tiers committed by §5.7 / §5.4.
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
}
