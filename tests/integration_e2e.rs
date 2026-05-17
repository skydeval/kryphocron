//! End-to-end public-surface integration tests.
//!
//! Drives the §4.3 pipeline (issue → bind → audit) through the
//! crate's public API for all four capability classes (user,
//! channel, substrate, moderation), one happy-path test and one
//! denial-path test per class. The companion `integration.rs`
//! suite pins structural type-existence; this suite exercises the
//! pipeline a downstream consumer (e.g., the Aurora-Locus
//! federation surface) would actually wire up.
//!
//! Requires the `test-support` feature:
//!
//! ```text
//! cargo test --features test-support --test integration_e2e
//! ```
//!
//! The feature exposes `AuthContext::new_for_test` and
//! `ServiceIdentity::new_for_test`, which bypass the verified-
//! evidence ingress discipline (§4.2). Without those, a consumer
//! has to stand up the full JWT-verification path to construct a
//! non-anonymous context, which is appropriate for production but
//! prohibitive for an integration suite.

#![cfg(feature = "test-support")]

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use kryphocron::{
    AttributionChain, AuditError, AuditSinks, AuthContext, AuthDenial, BindError,
    BindFailureReason, BindOutcomeRepr, CapabilityKind, CapabilitySet, ChannelAuditSink,
    CorrelationKey, DenialReason, Did, FallbackAuditSink, InspectionKind,
    InspectionNotification, InspectionNotificationQueueImpl, KeyId, ModerationAuditSink,
    Nsid, OracleSet, PipelineStage, PublicKey, Requester, ResourceId, Rkey,
    ServiceIdentity, SessionId, SignatureAlgorithm, SinkKind, SubstrateAuditSink,
    TraceId, UserAuditSink,
};
use kryphocron::audit::{
    BoundedString, ChannelAuditEvent, CompositeOpId, FallbackAuditEvent,
    ModerationAuditEvent, ModeratorRationale, SubstrateAuditEvent, UserAuditEvent,
    MAX_RATIONALE_LEN,
};
use kryphocron::authority::{
    issue_channel, issue_moderation, issue_substrate, issue_user, ChannelBinding,
    EmitToSyncChannel, ModerationCaseId, ModerationSubject, ModeratorRead, ScanShard,
    ScopeSelector, ShardId, ShardRange, ViewPrivate,
};
use kryphocron::oracle::{
    AudienceOracle, AudienceOracleQuery, AudienceState, BlockOracle, BlockOracleQuery,
    BlockState, MuteOracle, MuteOracleQuery, MuteState,
};

// ============================================================
// Capturing sinks built on the public trait surface.
// ============================================================
//
// The crate's own bind tests live inside the crate and reuse a
// pub(crate) `bind_test_fixtures` module. Out-of-crate integration
// tests rebuild the same fixtures against the public trait surface
// to demonstrate the wiring downstream consumers need to do.

struct CapturingUserSink {
    captured: Mutex<Vec<UserAuditEvent>>,
}
impl CapturingUserSink {
    fn new() -> Self {
        Self { captured: Mutex::new(Vec::new()) }
    }
    fn captured(&self) -> Vec<UserAuditEvent> {
        self.captured.lock().unwrap().clone()
    }
}
impl UserAuditSink for CapturingUserSink {
    fn record(&self, event: UserAuditEvent) -> Result<(), AuditError> {
        self.captured.lock().unwrap().push(event);
        Ok(())
    }
}

struct CapturingChannelSink {
    captured: Mutex<Vec<ChannelAuditEvent>>,
}
impl CapturingChannelSink {
    fn new() -> Self {
        Self { captured: Mutex::new(Vec::new()) }
    }
    fn captured(&self) -> Vec<ChannelAuditEvent> {
        self.captured.lock().unwrap().clone()
    }
}
impl ChannelAuditSink for CapturingChannelSink {
    fn record(&self, event: ChannelAuditEvent) -> Result<(), AuditError> {
        self.captured.lock().unwrap().push(event);
        Ok(())
    }
}

struct CapturingSubstrateSink {
    captured: Mutex<Vec<SubstrateAuditEvent>>,
}
impl CapturingSubstrateSink {
    fn new() -> Self {
        Self { captured: Mutex::new(Vec::new()) }
    }
    fn captured(&self) -> Vec<SubstrateAuditEvent> {
        self.captured.lock().unwrap().clone()
    }
}
impl SubstrateAuditSink for CapturingSubstrateSink {
    fn record(&self, event: SubstrateAuditEvent) -> Result<(), AuditError> {
        self.captured.lock().unwrap().push(event);
        Ok(())
    }
}

struct CapturingModerationSink {
    captured: Mutex<Vec<ModerationAuditEvent>>,
}
impl CapturingModerationSink {
    fn new() -> Self {
        Self { captured: Mutex::new(Vec::new()) }
    }
    fn captured(&self) -> Vec<ModerationAuditEvent> {
        self.captured.lock().unwrap().clone()
    }
}
impl ModerationAuditSink for CapturingModerationSink {
    fn record(&self, event: ModerationAuditEvent) -> Result<(), AuditError> {
        self.captured.lock().unwrap().push(event);
        Ok(())
    }
}

struct NoopFallback;
impl FallbackAuditSink for NoopFallback {
    fn record_panic(&self, _: SinkKind, _: TraceId, _: CapabilityKind, _: SystemTime) {}
    fn record_composite_failure(
        &self,
        _: TraceId,
        _: CompositeOpId,
        _: &[SinkKind],
        _: &[SinkKind],
        _: SystemTime,
    ) {}
    fn record_event(&self, _: FallbackAuditEvent) {}
}

struct CapturingInspectionQueue {
    captured: Mutex<Vec<(Did, InspectionNotification)>>,
}
impl CapturingInspectionQueue {
    fn new() -> Self {
        Self { captured: Mutex::new(Vec::new()) }
    }
    fn captured(&self) -> Vec<(Did, InspectionNotification)> {
        self.captured.lock().unwrap().clone()
    }
}
impl InspectionNotificationQueueImpl for CapturingInspectionQueue {
    fn enqueue(&self, owner: &Did, event: InspectionNotification) {
        self.captured.lock().unwrap().push((owner.clone(), event));
    }
}

struct ConfigurableBlockOracle {
    state: BlockState,
}
impl BlockOracle for ConfigurableBlockOracle {
    fn block_state(&self, _: &Did, _: &Did) -> BlockState {
        self.state.clone()
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

struct NoopAudienceOracle;
impl AudienceOracle for NoopAudienceOracle {
    fn audience_state(&self, _: &Did, _: &ResourceId) -> AudienceState {
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

struct NoopMuteOracle;
impl MuteOracle for NoopMuteOracle {
    fn mute_state(&self, _: &Did, _: &Did) -> MuteState {
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

// ============================================================
// Fixture bundle.
// ============================================================

struct Fixture {
    user: CapturingUserSink,
    channel: CapturingChannelSink,
    substrate: CapturingSubstrateSink,
    moderation: CapturingModerationSink,
    fallback: NoopFallback,
    inspection: CapturingInspectionQueue,
    correlation_key: CorrelationKey,
    block: ConfigurableBlockOracle,
    audience: NoopAudienceOracle,
    mute: NoopMuteOracle,
}

impl Fixture {
    fn new() -> Self {
        Self::with_block_state(BlockState::None)
    }

    fn with_block_state(state: BlockState) -> Self {
        Self {
            user: CapturingUserSink::new(),
            channel: CapturingChannelSink::new(),
            substrate: CapturingSubstrateSink::new(),
            moderation: CapturingModerationSink::new(),
            fallback: NoopFallback,
            inspection: CapturingInspectionQueue::new(),
            correlation_key: CorrelationKey::from_bytes([0u8; 32]),
            block: ConfigurableBlockOracle { state },
            audience: NoopAudienceOracle,
            mute: NoopMuteOracle,
        }
    }

    fn build_ctx(&self, requester: Requester) -> AuthContext<'_> {
        AuthContext::new_for_test(
            requester,
            TraceId::from_bytes([0xCD; 16]),
            AuditSinks::new(
                &self.user,
                &self.channel,
                &self.substrate,
                &self.moderation,
                &self.fallback,
                &self.inspection,
                &self.correlation_key,
            ),
            OracleSet::new(&self.block, &self.audience, &self.mute),
            AttributionChain::empty(),
            CapabilitySet::empty(),
        )
    }
}

// ============================================================
// Sample-value helpers.
// ============================================================

fn sample_did() -> Did {
    Did::new("did:plc:integration").unwrap()
}

fn sample_resource_id() -> ResourceId {
    ResourceId::new(
        sample_did(),
        Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
        Rkey::new("3jzfcijpj2z2a").unwrap(),
    )
}

fn sample_service_identity() -> ServiceIdentity {
    ServiceIdentity::new_for_test(
        sample_did(),
        KeyId::from_bytes([0u8; 32]),
        PublicKey::new(SignatureAlgorithm::Ed25519, [0u8; 32]),
        None,
    )
}

fn sample_channel_subject() -> ChannelBinding {
    ChannelBinding {
        peer: sample_service_identity(),
        session_id: SessionId::from_bytes([0u8; 32]),
    }
}

fn sample_substrate_subject() -> ScopeSelector {
    ScopeSelector::Shard(
        ShardRange::new(
            ShardId::from_bytes([0; 8]),
            ShardId::from_bytes([0xFF; 8]),
        )
        .unwrap(),
    )
}

fn sample_moderation_subject() -> ModerationSubject {
    ModerationSubject {
        resource: sample_resource_id(),
        case: ModerationCaseId::from_bytes([0u8; 16]),
    }
}

fn sample_rationale() -> ModeratorRationale {
    ModeratorRationale::Declared(
        BoundedString::<MAX_RATIONALE_LEN>::new("v0.1 integration test rationale").unwrap(),
    )
}

// ============================================================
// User class — happy + denial.
// ============================================================

/// User-class happy path: Did requester + ViewPrivate + clean
/// oracles → `bind` returns `Ok(BoundUserProof)`, one
/// `CapabilityBound` event captured with `outcome: Success`.
#[tokio::test]
async fn user_class_happy_path_bind_emits_capability_bound() {
    let fixture = Fixture::new();
    let ctx = fixture.build_ctx(Requester::Did(sample_did()));
    let proof = issue_user::<ViewPrivate>(&ctx, sample_resource_id())
        .expect("user-class issuance with Did requester should succeed");

    let bound = proof
        .bind(&ctx, &sample_resource_id())
        .await
        .expect("happy-path user-class bind should succeed");
    let _ = bound;

    let captured = fixture.user.captured();
    assert_eq!(captured.len(), 1, "one terminal audit event per bind");
    match &captured[0] {
        UserAuditEvent::CapabilityBound { capability, outcome, .. } => {
            assert_eq!(*capability, CapabilityKind::ViewPrivate);
            assert!(matches!(outcome, BindOutcomeRepr::Success));
        }
        other => panic!("expected CapabilityBound, got {other:?}"),
    }
}

/// User-class denial path: Did requester + ViewPrivate + Mutual
/// block at the §4.3 stage 2 oracle consultation → bind returns
/// `Err(DeniedAtPipeline { stage: BlockConsultation, .. })`, one
/// `CapabilityIssuanceDenied` event captured with `reason:
/// Blocked`.
#[tokio::test]
async fn user_class_denial_path_block_oracle_emits_issuance_denied() {
    let fixture = Fixture::with_block_state(BlockState::Mutual);
    let ctx = fixture.build_ctx(Requester::Did(sample_did()));
    let proof = issue_user::<ViewPrivate>(&ctx, sample_resource_id())
        .expect("issuance precedes oracle consultation in v0.1 pipeline");

    let err = match proof.bind(&ctx, &sample_resource_id()).await {
        Err(e) => e,
        Ok(_) => panic!("Mutual block should deny bind at stage 2"),
    };
    match err {
        BindError::DeniedAtPipeline { stage, reason } => {
            assert_eq!(stage, PipelineStage::BlockConsultation);
            assert!(matches!(reason, DenialReason::Blocked { .. }));
        }
        other => panic!("expected DeniedAtPipeline(BlockConsultation), got {other:?}"),
    }

    let captured = fixture.user.captured();
    assert_eq!(captured.len(), 1);
    match &captured[0] {
        UserAuditEvent::CapabilityIssuanceDenied { reason, .. } => {
            assert!(matches!(reason, DenialReason::Blocked { .. }));
        }
        other => panic!("expected CapabilityIssuanceDenied, got {other:?}"),
    }
}

// ============================================================
// Channel class — happy + denial.
// ============================================================

/// Channel-class happy path: Did requester + EmitToSyncChannel
/// channel subject → `bind` returns `Ok(BoundChannelProof)`, one
/// `ChannelBound` event captured.
#[tokio::test]
async fn channel_class_happy_path_bind_emits_channel_bound() {
    let fixture = Fixture::new();
    let ctx = fixture.build_ctx(Requester::Did(sample_did()));
    let proof = issue_channel::<EmitToSyncChannel>(&ctx, sample_channel_subject())
        .expect("channel-class issuance with Did requester should succeed");

    let bound = proof
        .bind(&ctx, &sample_channel_subject())
        .await
        .expect("happy-path channel-class bind should succeed");
    let _ = bound;

    let captured = fixture.channel.captured();
    assert_eq!(captured.len(), 1);
    match &captured[0] {
        ChannelAuditEvent::ChannelBound { endpoint, outcome, .. } => {
            assert_eq!(*endpoint, CapabilityKind::EmitToSyncChannel);
            assert!(matches!(outcome, BindOutcomeRepr::Success));
        }
        other => panic!("expected ChannelBound, got {other:?}"),
    }
}

/// Channel-class denial path: Anonymous requester →
/// `issue_channel` returns `AuthDenial::RequesterLacksAuthority`
/// at the §4.3 stage 1 chokepoint. Issuance denial fires no audit
/// (audit reflects action, not intent — the bind never happened);
/// the test pins both the error variant and the absence of audit.
#[tokio::test]
async fn channel_class_denial_path_anonymous_at_chokepoint() {
    let fixture = Fixture::new();
    let ctx = fixture.build_ctx(Requester::Anonymous);

    let err = match issue_channel::<EmitToSyncChannel>(&ctx, sample_channel_subject()) {
        Err(e) => e,
        Ok(_) => panic!("anonymous requester must be denied at channel chokepoint"),
    };
    assert!(
        matches!(err, AuthDenial::RequesterLacksAuthority { .. }),
        "expected RequesterLacksAuthority, got {err:?}",
    );

    assert_eq!(
        fixture.channel.captured().len(),
        0,
        "issuance denial does not emit audit (audit fires at bind)",
    );
}

// ============================================================
// Substrate class — happy + denial.
// ============================================================

/// Substrate-class happy path: Service requester + ScanShard +
/// shard range → `bind` returns `Ok(BoundSubstrateProof)`, one
/// `ScopeBound` event captured.
#[tokio::test]
async fn substrate_class_happy_path_bind_emits_scope_bound() {
    let fixture = Fixture::new();
    let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
    let proof = issue_substrate::<ScanShard>(&ctx, sample_substrate_subject())
        .expect("substrate-class issuance with Service requester should succeed");

    let bound = proof
        .bind(&ctx, &sample_substrate_subject())
        .await
        .expect("happy-path substrate-class bind should succeed");
    let _ = bound;

    let captured = fixture.substrate.captured();
    assert_eq!(captured.len(), 1);
    match &captured[0] {
        SubstrateAuditEvent::ScopeBound { capability, outcome, .. } => {
            assert_eq!(*capability, CapabilityKind::ScanShard);
            assert!(matches!(outcome, BindOutcomeRepr::Success));
        }
        other => panic!("expected ScopeBound, got {other:?}"),
    }
}

/// Substrate-class denial path: Did requester (user-class
/// identity attempting substrate authority) → `issue_substrate`
/// returns `AuthDenial::RequesterLacksAuthority`. Substrate-class
/// accepts Service principals only.
#[tokio::test]
async fn substrate_class_denial_path_did_at_chokepoint() {
    let fixture = Fixture::new();
    let ctx = fixture.build_ctx(Requester::Did(sample_did()));

    let err = match issue_substrate::<ScanShard>(&ctx, sample_substrate_subject()) {
        Err(e) => e,
        Ok(_) => panic!("Did requester must be denied at substrate chokepoint"),
    };
    assert!(
        matches!(err, AuthDenial::RequesterLacksAuthority { .. }),
        "expected RequesterLacksAuthority, got {err:?}",
    );

    assert_eq!(fixture.substrate.captured().len(), 0);
}

// ============================================================
// Moderation class — happy + denial.
// ============================================================

/// Moderation-class happy path: Service requester + ModeratorRead
/// + ModerationSubject + Declared rationale → `bind` returns
/// `Ok(BoundModerationProof)`, one `ModeratorInspected` event
/// captured AND one `InspectionNotification` enqueued (§6.7
/// dual-emit).
#[tokio::test]
async fn moderation_class_happy_path_bind_emits_inspected_and_notification() {
    let fixture = Fixture::new();
    let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
    let proof = issue_moderation::<ModeratorRead>(&ctx, sample_moderation_subject())
        .expect("moderation-class issuance with Service requester should succeed");

    let bound = proof
        .bind(&ctx, &sample_moderation_subject(), sample_rationale())
        .await
        .expect("happy-path moderation-class bind should succeed");
    let _ = bound;

    let audit = fixture.moderation.captured();
    assert_eq!(audit.len(), 1);
    match &audit[0] {
        ModerationAuditEvent::ModeratorInspected { rationale, .. } => {
            assert!(matches!(rationale, ModeratorRationale::Declared(_)));
        }
        other => panic!("expected ModeratorInspected, got {other:?}"),
    }

    let notifications = fixture.inspection.captured();
    assert_eq!(
        notifications.len(),
        1,
        "§6.7 dual-emit: ModeratorRead bind enqueues one inspection notification",
    );
    match &notifications[0].1.kind {
        InspectionKind::ModeratorRead { .. } => {}
        other => panic!("expected InspectionKind::ModeratorRead, got {other:?}"),
    }
}

/// Moderation-class denial path: Anonymous requester →
/// `issue_moderation` returns
/// `AuthDenial::RequesterLacksAuthority`. Moderation-class
/// accepts Service principals only.
#[tokio::test]
async fn moderation_class_denial_path_anonymous_at_chokepoint() {
    let fixture = Fixture::new();
    let ctx = fixture.build_ctx(Requester::Anonymous);

    let err = match issue_moderation::<ModeratorRead>(&ctx, sample_moderation_subject()) {
        Err(e) => e,
        Ok(_) => panic!("anonymous requester must be denied at moderation chokepoint"),
    };
    assert!(
        matches!(err, AuthDenial::RequesterLacksAuthority { .. }),
        "expected RequesterLacksAuthority, got {err:?}",
    );

    assert_eq!(fixture.moderation.captured().len(), 0);
    assert_eq!(fixture.inspection.captured().len(), 0);
}

// ============================================================
// Compile-time hint: BindFailureReason and other surface items
// are exercised by the audit-event matches above; this import is
// kept so the `use` line up top doesn't go dead if future tests
// remove a match arm.
// ============================================================

#[allow(dead_code)]
fn _surface_pin(_: &BindFailureReason) {}
