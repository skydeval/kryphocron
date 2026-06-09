//! External-crate construction tests for the public constructors added for
//! consumer use: the `verify_jwt` local-audience [`ServiceIdentity`] and the
//! [`DidDocument`] / [`DidService`] values an operator-implemented
//! `DidResolver` must return. These live at the external-crate compilation
//! boundary, proving the constructors are genuinely reachable by consumers
//! (not just `pub(crate)` / `test-support`-gated).

use std::time::{Duration, SystemTime};

use kryphocron::resolver::{DidDocument, DidService};
use kryphocron::{Did, KeyId, PublicKey, ServiceIdentity, SignatureAlgorithm};

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
