//! §4.1 Tier model and §4.4 tier-aware envelope types.
//!
//! The tier system encodes a record's visibility class as a
//! type-level property. A function emitting to a public surface
//! takes `Tiered<T, PublicTier>`; passing in a
//! `Tiered<T, PrivateTier>` is a compile error, not a runtime
//! check.
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
//!   ([`Tier::visible_to`]) is.

use core::marker::PhantomData;

use crate::proto::{Nsid, UnknownNsid};
use crate::sealed;

/// Tier classification for substrate-managed records.
///
/// Two tiers in v1: [`Tier::Public`] (default-visible) and
/// [`Tier::Private`] (audience-gated). `#[non_exhaustive]` from
/// day one so future tier additions ship as backward-compatible
/// minor-version changes.
///
/// See §4.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Public records. Visible to anyone.
    Public,
    /// Private records. Visible only to authorized audiences.
    Private,
}

impl Tier {
    /// Map an NSID to its tier classification via the closed-
    /// namespace registry.
    ///
    /// Phase 1 ships the function shape; the registry itself
    /// lives in the companion `kryphocron-lexicons` crate
    /// (Phase 2; §5.3 / §5.4). Calling this in Phase 1 always
    /// returns [`UnknownNsid::NotRegistered`] — there is no
    /// registry to consult yet.
    ///
    /// See §4.1 NSID-to-tier mapping.
    pub fn from_nsid(nsid: &Nsid) -> Result<Tier, UnknownNsid> {
        // Phase 1: no registry. Phase 2 wires
        // `kryphocron_lexicons::registry`.
        Err(UnknownNsid::NotRegistered(nsid.clone()))
    }

    /// Visibility predicate against an [`crate::AuthContext`].
    ///
    /// `Hidden` and `Forbidden` are distinct **internally** —
    /// audit pipelines and operators distinguish "exists but
    /// audience-gated for this viewer" from "policy-forbidden" —
    /// but they collapse to the same wire response (per §4.1's
    /// closed-namespace non-enumeration discipline).
    #[must_use]
    pub fn visible_to(self, _ctx: &crate::ingress::AuthContext<'_>) -> Visibility {
        // Phase 1: shape only. The Phase 4 implementation walks
        // the §4.3 pipeline; the public predicate result is one of
        // three Visibility variants.
        unimplemented!("§4.1 Tier::visible_to: Phase 4 wires the pipeline");
    }
}

/// Result of [`Tier::visible_to`].
///
/// `Hidden` and `Forbidden` are distinct internally; both
/// collapse to byte-identical wire responses at the HTTP layer
/// (§4.1 closed-namespace failure modes; §4.6 non-enumeration).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// Viewer is authorized to see the record.
    Visible,
    /// Viewer is not in the record's audience. Indistinguishable
    /// from `Forbidden` on the public wire.
    Hidden,
    /// Viewer is policy-forbidden from the record. Indistinguishable
    /// from `Hidden` on the public wire.
    Forbidden,
}

impl Visibility {
    /// True iff the viewer may read the record.
    #[must_use]
    pub fn allows_read(self) -> bool {
        matches!(self, Visibility::Visible)
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
/// codegen pipeline, Phase 2) implement [`HasNsid`]. Consumers
/// cannot declare arbitrary types as kryphocron records.
pub trait HasNsid: sealed::Sealed + 'static {
    /// The NSID identifying this record type.
    const NSID: &'static str;
    /// The tier this record type belongs to.
    type Tier: TierWitness;

    /// Convenience: produce a typed [`Nsid`] handle.
    ///
    /// Default impl wraps [`Self::NSID`]; tests for individual
    /// record types verify the parse succeeds against
    /// `proto-blue-lexicon` once Phase 2 wires it.
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
        // Pin the v1 variant set. From inside the defining crate the
        // compiler treats #[non_exhaustive] enums as exhaustive, so
        // adding a new variant breaks this match — the failure is
        // the intended signal that downstream code needs review.
        let t = Tier::Public;
        match t {
            Tier::Public | Tier::Private => {}
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
    fn from_nsid_phase1_always_unknown() {
        // Phase 1: registry doesn't exist yet. Phase 2 wires it.
        let nsid = Nsid::new("tools.kryphocron.feed.postPrivate").unwrap();
        assert!(matches!(Tier::from_nsid(&nsid), Err(UnknownNsid::NotRegistered(_))));
    }
}
