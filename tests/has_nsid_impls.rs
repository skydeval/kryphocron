//! §5.3 / §5.4 verification of the build-script-emitted `HasNsid` impls.
//!
//! Confirms that every registered lexicon record type carries a `HasNsid`
//! impl whose runtime NSID and type-level tier agree with the lexicon
//! registry — the property that makes `Tiered<T, Ti>` trustworthy.

use kryphocron::{
    HasNsid, PrivateTier, PublicTier, TierWitness, KRYPHOCRON_IMPLEMENTED_NSIDS,
    KRYPHOCRON_LEXICON_REGISTRY,
};
use kryphocron_lexicons::tools::kryphocron::{feed, graph, policy};

/// Assert a record type's runtime NSID and that its type-level tier agrees
/// with the lexicon registry's tier for that NSID.
fn check<T: HasNsid>(nsid: &str) {
    assert_eq!(T::NSID, nsid, "HasNsid::NSID");
    let registry_tier = KRYPHOCRON_LEXICON_REGISTRY
        .iter()
        .find(|e| e.nsid == nsid)
        .unwrap_or_else(|| panic!("{nsid} missing from registry"))
        .tier;
    assert_eq!(
        <T::Tier as TierWitness>::TIER,
        registry_tier,
        "type-level tier for {nsid} disagrees with the registry"
    );
}

// Compile-time tier assertions: these signatures only accept a type whose
// `HasNsid::Tier` is exactly the named witness.
fn assert_public<T: HasNsid<Tier = PublicTier>>() {}
fn assert_private<T: HasNsid<Tier = PrivateTier>>() {}

#[test]
fn implemented_set_equals_registry() {
    let mut impls: Vec<&str> = KRYPHOCRON_IMPLEMENTED_NSIDS.to_vec();
    impls.sort_unstable();
    let mut registry: Vec<&str> = KRYPHOCRON_LEXICON_REGISTRY.iter().map(|e| e.nsid).collect();
    registry.sort_unstable();
    assert_eq!(
        impls, registry,
        "every registered lexicon must have a HasNsid impl, and vice versa"
    );
}

#[test]
fn every_record_type_carries_correct_nsid_and_tier() {
    // Public tier (4).
    check::<feed::post_public::Main>("tools.kryphocron.feed.postPublic");
    check::<feed::like::Main>("tools.kryphocron.feed.like");
    check::<feed::repost::Main>("tools.kryphocron.feed.repost");
    check::<feed::threadgate::Main>("tools.kryphocron.feed.threadgate");
    // Private tier (4).
    check::<feed::post_private::Main>("tools.kryphocron.feed.postPrivate");
    check::<graph::block::Main>("tools.kryphocron.graph.block");
    check::<graph::mute::Main>("tools.kryphocron.graph.mute");
    check::<policy::audience::Main>("tools.kryphocron.policy.audience");
}

#[test]
fn type_level_tier_witnesses_compile() {
    // >=2 per tier — compile-time proof the witness associated type is right.
    assert_public::<feed::post_public::Main>();
    assert_public::<feed::like::Main>();
    assert_private::<feed::post_private::Main>();
    assert_private::<graph::block::Main>();
}
