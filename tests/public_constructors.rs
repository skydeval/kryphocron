//! External-crate construction tests for the public constructors added for
//! consumer use: the `verify_jwt` local-audience [`ServiceIdentity`], the
//! [`DidDocument`] / [`DidService`] values an operator-implemented
//! `DidResolver` must return, and the §8.3 at-rest decode inputs
//! ([`EncodedRecord`] / [`DecodeContext`]) a host rebuilds from storage. These
//! live at the external-crate compilation boundary, proving the constructors
//! are genuinely reachable by consumers (not just `pub(crate)` /
//! `test-support`-gated) — the `#[non_exhaustive]` types in particular cannot
//! be struct-literal-constructed from here, so a passing test proves the
//! `::new` path is the reachable one.

use std::time::{Duration, SystemTime};

use kryphocron::resolver::{DidDocument, DidService};
use kryphocron::{
    AtUri, CodecId, DecodeContext, Did, EncodedRecord, KeyId, Nsid, PublicKey, RecordKey,
    RotationGenerationMark, ServiceIdentity, SignatureAlgorithm, TraceId,
};

fn sample_pubkey() -> PublicKey {
    PublicKey::new(SignatureAlgorithm::Ed25519, [7u8; 32])
}

#[test]
fn service_identity_constructible_externally() {
    let did = Did::new("did:plc:audience123").expect("valid did");
    let identity = ServiceIdentity::new(
        did.clone(),
        KeyId::from_bytes([1u8; 32]),
        sample_pubkey(),
        None, // fresh service: no prior rotation chain
    );
    // `verify_jwt`'s audience check consults only `service_did()`; confirm it
    // round-trips, which is the audience-binding property consumers rely on.
    assert_eq!(identity.service_did(), &did);
}

#[test]
fn did_document_and_service_constructible_externally() {
    let did = Did::new("did:plc:doc123").expect("valid did");
    let service = DidService::new(
        "#atproto_pds".to_string(),
        "AtprotoPersonalDataServer".to_string(),
        "https://pds.example".to_string(),
    );
    let doc = DidDocument::new(
        did.clone(),
        vec![(KeyId::from_bytes([2u8; 32]), sample_pubkey())], // verification_methods
        vec![],                                                // rotation_history
        vec![service],                                         // services
        vec!["at://handle.example".to_string()],               // also_known_as
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(3600),
    );
    assert_eq!(doc.did, did);
    assert_eq!(doc.verification_methods.len(), 1);
    assert_eq!(doc.services.len(), 1);
}

#[test]
fn at_rest_decode_inputs_constructible_externally() {
    // The §8.3 decode-side symmetry (0.3.1): a host rebuilds the at-rest decode
    // inputs from persisted lexicon field values. Both types are
    // `#[non_exhaustive]`, so struct-literal construction is forbidden here —
    // reaching them is only possible via `::new`, which is the whole point of
    // the 0.3.1 additions. `operator_context` is passed via `Default::default()`
    // so the test needs no `smallvec` dependency.
    let codec = CodecId::new("laquna/0.2").expect("valid codec id");
    let generation = RotationGenerationMark::new("000042").expect("valid mark");
    let record = EncodedRecord::new(codec.clone(), b"CIPHERTEXT".to_vec(), Some(generation));
    // Fields are `pub`; reading them back confirms the constructor stored them.
    assert_eq!(record.codec, codec);
    assert_eq!(record.content, b"CIPHERTEXT");
    assert_eq!(record.generation.as_ref().map(RotationGenerationMark::as_str), Some("000042"));

    let did = Did::new("did:plc:exampleexampleexample").expect("valid did");
    let nsid = Nsid::new("tools.kryphocron.feed.postPrivate").expect("valid nsid");
    let ctx = DecodeContext::new(
        nsid.clone(),
        RecordKey::new("3kabcdefghij2").expect("valid rkey"),
        did.clone(),
        Some(
            AtUri::new("at://did:plc:x/tools.kryphocron.policy.audience/3jzfcijpj2z2a")
                .expect("valid at-uri"),
        ),
        TraceId::from_bytes([7u8; 16]),
        Default::default(),
    );
    assert_eq!(ctx.originator, did);
    assert_eq!(ctx.nsid, nsid);
    assert!(ctx.audience_list.is_some());
}
