//! Confirms the umbrella `kryphocron::lexicons()` re-export resolves and
//! returns a populated collection. The full validate_record wiring is
//! exercised in `kryphocron-lexicons/tests/lexicons_accessor.rs`, where
//! the proto-blue dependency is already a direct dependency.

#[test]
fn umbrella_lexicons_reexport_is_populated() {
    // Method resolution reaches `Lexicons::doc_count` without naming the
    // type, so this needs no proto-blue dependency on the umbrella crate.
    let docs = kryphocron::lexicons();
    assert!(
        docs.doc_count() >= kryphocron::KRYPHOCRON_LEXICON_REGISTRY.len(),
        "lexicons() should expose at least as many docs as the registry lists"
    );
}
