// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! §4.3 capability issuance, proof types, and the v1 capability
//! vocabulary.
//!
//! Four issuance chokepoints — one per capability class — and
//! four parallel proof families. The chokepoints are the **only**
//! way to produce proof values; consumer code cannot construct
//! a proof value via struct-literal syntax because the proof
//! types carry private `PhantomData<sealed::Token>` fields.

pub(crate) mod capability;
pub(crate) mod moderation;
pub(crate) mod predicate;
pub(crate) mod proof;
pub(crate) mod subjects;
pub(crate) mod v1;

use std::sync::OnceLock;
use std::time::Instant;

use crate::ingress::{AuthContext, Requester};
use crate::proto::Did;

pub use self::capability::{
    CapabilityClass, CapabilityKind, CapabilitySemantics, CapabilitySet, Endpoint,
    ModerationCapability, OracleConsultations, OracleResultsForCapability, SubstrateScope,
    UserCapability,
};
pub use self::moderation::{
    InspectionKind, InspectionNotification, InspectionNotificationQueueImpl,
    InspectionNotificationQueueReader, NoInspectionNotifications, NotificationId,
};
pub use self::predicate::{
    AuthDenial, BindError, BindFailureReason, BindOutcomeRepr, DenialReason, IssuancePolicy,
    PipelineStage, PredicateContext, SemVer,
};
pub use self::proof::{
    AuthorityId, BoundChannelProof, BoundModerationProof, BoundSubstrateProof,
    BoundUserProof, ChannelProof, ChannelProofRef, ModerationProof, ModerationProofRef,
    SubstrateProof, SubstrateProofRef, UserProof, UserProofRef,
};
pub use self::subjects::{
    AudienceListId, ChannelBinding, HasResourceLocation, ManageAudienceSubject,
    ModerationCaseId, ModerationSubject, RecordStateFilter, ResourceId, ScopeError,
    ScopeSelector, ShardId, ShardRange, TimeWindow,
};
pub use self::v1::{
    AppViewSync, DeletePrivatePost, DeletePrivatePostOracleResults, EditPrivatePost,
    EditPrivatePostOracleResults, EmitToSyncChannel, GarbageCollect, GraphSync,
    ManageAudience, ManageAudienceOracleResults, ModeratorRead, ModeratorRestore,
    ModeratorTakedown, ParticipatePrivate, ParticipatePrivateOracleResults,
    ReplicatePrivate, ScanShard, ViewPrivate, ViewPrivateOracleResults,
};

// ============================================================
// Issuance chokepoints (§4.3).
// ============================================================
//
// Four functions, one per class. Each runs the §4.3 stage 1
// requester-authority check and constructs the sealed
// `*Proof<C>` value on success. Stage 0 (lexicon deprecation
// gate) and stage 2 (subject ownership) defer to the bind
// pipeline at `*Proof::bind` (see [`crate::authority::proof`]).

/// Issue a user-class capability proof (§4.3).
///
/// Pipeline (Phase 7c v0.1):
///
/// - **Stage 1 — requester authority.** User-class accepts
///   [`Requester::Did`] (the user themselves) and
///   [`Requester::Service`] (a substrate dispatching on the
///   user's behalf). [`Requester::Anonymous`] fails closed with
///   [`AuthDenial::RequesterLacksAuthority`].
/// - **Stage 3 — proof construction.** Builds a
///   [`UserProof<C>`] with `issued_at = Instant::now()` and a
///   process-static [`AuthorityId`] (see
///   `process_authority_id`).
///
/// Stage 0 (§5.6 lexicon-deprecation gate) and stage 2 (subject
/// ownership / authority check) defer to bind (Phase 7d). Stage 0
/// requires generic NSID extraction from the typed `Subject`; stage 2
/// is the bind-time predicate's domain
/// ([`DenialReason::OwnershipCheckFailed`](crate::DenialReason)).
///
/// # Errors
///
/// Returns [`AuthDenial::RequesterLacksAuthority`] if the
/// requester is anonymous. Future variants (oracle-staleness,
/// rate-limiting, JWT-scope mismatch routed through
/// [`check_jwt_scope_for`]) land in subsequent phases.
pub fn issue_user<C>(
    ctx: &AuthContext<'_>,
    subject: <C as UserCapability>::Subject,
) -> Result<UserProof<C>, AuthDenial>
where
    C: UserCapability + IssuancePolicy,
{
    let requester = stage1_extract_requester_did(ctx, CapabilityClass::User, true)?;
    Ok(UserProof::new_internal(
        requester,
        subject,
        Instant::now(),
        process_authority_id(),
        ctx.trace_id(),
    ))
}

/// Issue a channel-class capability proof (§4.3).
///
/// Pipeline (Phase 7c v0.1):
///
/// - **Stage 1 — requester authority.** Channel-class accepts
///   [`Requester::Did`] (a user dispatching a channel
///   subscription) and [`Requester::Service`] (an operator
///   dispatching channel events on the user's behalf).
///   [`Requester::Anonymous`] fails closed.
/// - **Stage 3 — proof construction.** Builds a
///   [`ChannelProof<E>`] with `issued_at = Instant::now()` and a
///   process-static [`AuthorityId`].
///
/// Stage 0 (lexicon deprecation) does not apply to channel-class
/// — channel subjects ([`crate::authority::ChannelBinding`])
/// carry no NSID.
/// Stage 2 (endpoint validation) is the bind-time predicate's
/// domain.
///
/// # Errors
///
/// Returns [`AuthDenial::RequesterLacksAuthority`] if the
/// requester is anonymous.
pub fn issue_channel<E>(
    ctx: &AuthContext<'_>,
    subject: <E as Endpoint>::Subject,
) -> Result<ChannelProof<E>, AuthDenial>
where
    E: Endpoint,
{
    let requester = stage1_extract_requester_did(ctx, CapabilityClass::Channel, true)?;
    Ok(ChannelProof::new_internal(
        requester,
        subject,
        Instant::now(),
        process_authority_id(),
        ctx.trace_id(),
    ))
}

/// Issue a substrate-class capability proof (§4.3).
///
/// Substrate-class issuance accepts only non-interactive service
/// principals (§4.6 read-everything-authority discipline).
///
/// Pipeline (Phase 7c v0.1):
///
/// - **Stage 1 — requester authority.** Substrate-class accepts
///   [`Requester::Service`] only. [`Requester::Did`] and
///   [`Requester::Anonymous`] both fail closed with
///   [`AuthDenial::RequesterLacksAuthority`] — users cannot issue
///   substrate capabilities under any circumstance.
/// - **Stage 3 — proof construction.** Builds a
///   [`SubstrateProof<S>`] with `issued_at = Instant::now()` and a
///   process-static [`AuthorityId`].
///
/// Stage 0 does not apply (substrate subjects
/// [`crate::authority::ScopeSelector`] carry no NSID). Stage 2
/// (scope-vs-trust-declaration check) is the bind-time
/// predicate's domain; the
/// [`crate::ingress::ServiceTrustDeclaration`] surface that
/// powers it lands as part of Phase 7d.
///
/// # Errors
///
/// Returns [`AuthDenial::RequesterLacksAuthority`] for any
/// non-Service requester.
pub fn issue_substrate<S>(
    ctx: &AuthContext<'_>,
    subject: <S as SubstrateScope>::Subject,
) -> Result<SubstrateProof<S>, AuthDenial>
where
    S: SubstrateScope,
{
    let requester = stage1_extract_requester_did(ctx, CapabilityClass::Substrate, false)?;
    Ok(SubstrateProof::new_internal(
        requester,
        subject,
        Instant::now(),
        process_authority_id(),
        ctx.trace_id(),
    ))
}

/// Issue a moderation-class capability proof (§4.3).
///
/// Moderation-class issuance accepts only service principals
/// per §4.3 moderation-as-service discipline (moderators dispatch
/// through a service-identity-bearing operator surface, never
/// directly as user-class requesters).
///
/// Pipeline (Phase 7c v0.1):
///
/// - **Stage 1 — requester authority.** Moderation-class accepts
///   [`Requester::Service`] only. [`Requester::Did`] and
///   [`Requester::Anonymous`] both fail closed.
/// - **Stage 3 — proof construction.** Builds a
///   [`ModerationProof<C>`] with `issued_at = Instant::now()` and
///   a process-static [`AuthorityId`].
///
/// Stage 0 deferred to bind for moderation subjects that carry
/// an NSID via their inner [`crate::ResourceId`] (Phase 7d).
/// Stage 2 (jurisdiction check — does this moderator's
/// service-identity carry authority over the moderation target?)
/// is also bind-time. The v0.1 jurisdiction model is "any
/// Service requester is admissible at the chokepoint"; the
/// bind-time predicate refines it once the operator-managed
/// moderator-role surface lands. See note for v0.2
/// jurisdiction model.
///
/// `ModeratorRead` bind separately emits two audit events per
/// §4.9 (one to the moderation sink, one to the owner's
/// inspection-notification queue) — issuance does not emit;
/// audit fires at bind only.
///
/// # Errors
///
/// Returns [`AuthDenial::RequesterLacksAuthority`] for any
/// non-Service requester.
pub fn issue_moderation<C>(
    ctx: &AuthContext<'_>,
    subject: <C as ModerationCapability>::Subject,
) -> Result<ModerationProof<C>, AuthDenial>
where
    C: ModerationCapability,
{
    let requester = stage1_extract_requester_did(ctx, CapabilityClass::Moderation, false)?;
    Ok(ModerationProof::new_internal(
        requester,
        subject,
        Instant::now(),
        process_authority_id(),
        ctx.trace_id(),
    ))
}

// ============================================================
// §7.2 JWT-scope enforcement (Phase 4a).
// ============================================================

/// Match the verified JWT's scope against capability `C`'s
/// declared scope requirement (§7.2).
///
/// `Ok(())` if `C::required_jwt_scope()` is `None` (no scope
/// requirement applies) or if the JWT's scope set contains the
/// required value. `Err(AuthDenial::ScopeMismatch)` otherwise.
///
/// **Empty scope is fail-closed** per §7.2: a JWT with no scope
/// claim presented for a capability that requires a scope value
/// fails with `granted: SmallVec::new()`. Issuance paths surface
/// this as
/// [`crate::audit::UserAuditEvent::CapabilityIssuanceDenied`] with
/// [`crate::authority::DenialReason::JwtScopeInsufficient`] —
/// Phase 4a wires
/// the matching mechanism; the bind-pipeline surface that
/// translates the denial to the audit event is staged for the
/// later Phase 4 sub-phases that bring `issue_user::<C>` out of
/// stub state.
///
/// # Errors
///
/// Returns [`AuthDenial::ScopeMismatch`] when `C` requires a
/// scope and the JWT's `JwtScope::scopes` does not contain it.
pub fn check_jwt_scope_for<C: IssuancePolicy>(
    jwt_scope: &crate::verification::JwtScope,
) -> Result<(), AuthDenial> {
    check_jwt_scope_required(<C as IssuancePolicy>::required_jwt_scope(), jwt_scope)
}

/// The scope-matching primitive [`check_jwt_scope_for`] wraps.
/// Crate-internal so tests can pin scope-required behavior
/// without standing up a full `IssuancePolicy` impl (which would
/// require a sealed `OracleResultsForCapability` type that only
/// the `capability_marker!` macro can produce).
pub(crate) fn check_jwt_scope_required(
    required: Option<&'static str>,
    jwt_scope: &crate::verification::JwtScope,
) -> Result<(), AuthDenial> {
    let Some(required) = required else {
        return Ok(());
    };
    if jwt_scope.scopes.iter().any(|s| s == required) {
        return Ok(());
    }
    Err(AuthDenial::ScopeMismatch {
        required: required.to_string(),
        granted: jwt_scope.scopes.clone(),
    })
}

// ============================================================
// Phase 7c §4.3 issuance internals.
// ============================================================

/// §4.3 stage 1: extract the requester [`Did`] from `ctx`,
/// failing with [`AuthDenial::RequesterLacksAuthority`] if the
/// requester does not carry the authority required to issue
/// `class`.
///
/// `accept_did` controls whether [`Requester::Did`] is admitted:
/// user-class and channel-class pass `true` (interactive issuance
/// allowed); substrate-class and moderation-class pass `false`
/// (Service-only issuance, per §4.6 read-everything-authority and
/// §4.3 moderation-as-service discipline). [`Requester::Anonymous`]
/// is rejected by every chokepoint regardless of `accept_did`.
fn stage1_extract_requester_did(
    ctx: &AuthContext<'_>,
    class: CapabilityClass,
    accept_did: bool,
) -> Result<Did, AuthDenial> {
    match ctx.requester() {
        Requester::Did(did) if accept_did => Ok(did.clone()),
        Requester::Service(service) => Ok(service.service_did().clone()),
        other => Err(AuthDenial::RequesterLacksAuthority {
            class,
            found: other.kind(),
        }),
    }
}

/// §4.3 stage 0 / §5.6: consult the
/// [`crate::KRYPHOCRON_LEXICON_REGISTRY`] for `nsid`'s
/// deprecation status, returning the matching
/// [`DenialReason::CapabilityDeprecated`] when the lexicon is
/// outright deprecated, `Ok(())` when active or inside an
/// operator-configured grace window.
///
/// `now_unix_seconds` is supplied by the caller (typically
/// `SystemTime::now()`'s seconds-since-epoch); pulling it out of
/// the helper keeps the function deterministic for tests.
///
/// NSIDs not present in the registry pass — the closed-namespace
/// registry is authoritative for v1 lexicons; non-v1 NSIDs aren't
/// gated by §5.6 and surface as predicate-stage failures via the
/// capability's own logic.
///
/// Consumed by Phase 7d's [`UserProof::bind`] (Write-semantics
/// only) and [`ModerationProof::bind`] (always) pipelines at
/// stage 0.
pub(crate) fn check_stage_0_deprecation(
    nsid: &crate::proto::Nsid,
    now_unix_seconds: i64,
) -> Result<(), DenialReason> {
    use kryphocron_lexicons::DeprecationState;
    for entry in crate::KRYPHOCRON_LEXICON_REGISTRY {
        if entry.nsid == nsid.as_str() {
            return match entry.deprecation {
                DeprecationState::Active => Ok(()),
                DeprecationState::Deprecated {
                    since_version,
                    successor,
                } => Err(DenialReason::CapabilityDeprecated {
                    nsid: entry.nsid,
                    since_version,
                    successor,
                }),
                DeprecationState::DeprecatedWithGrace {
                    since_version,
                    grace_until_unix_seconds,
                    successor,
                } => {
                    if now_unix_seconds > grace_until_unix_seconds {
                        Err(DenialReason::CapabilityDeprecated {
                            nsid: entry.nsid,
                            since_version,
                            successor,
                        })
                    } else {
                        // Inside the grace window: bind proceeds.
                        // Operators wanting an audit signal during
                        // grace install a `DeprecatedWriteDuringGrace`
                        // emission on top of bind's own audit emit
                        // (Phase 7d ships the gate; the grace-window
                        // audit shim is a v0.2 enrichment).
                        Ok(())
                    }
                }
                // DeprecationState is #[non_exhaustive] from the
                // lexicon crate. Future variants fail closed at
                // bind: an unknown deprecation state shouldn't be
                // bypassed silently. Reachable only after a
                // lexicon-crate version bump that adds a variant
                // without bumping the kryphocron-side handling.
                _ => Err(DenialReason::CapabilityDeprecated {
                    nsid: entry.nsid,
                    since_version: kryphocron_lexicons::SemVer::new(0, 0, 0),
                    successor: None,
                }),
            };
        }
    }
    Ok(())
}

/// Process-static [`AuthorityId`] (§4.3).
///
/// Lazy-initialized from the OS CSPRNG on first use via
/// [`OnceLock`] + [`getrandom::getrandom`]. The `AuthorityId`
/// names the substrate's authority-module instance for the
/// lifetime of the process; multiple substrates running in
/// distinct processes will pick distinct ids with overwhelming
/// probability (16 bytes from CSPRNG).
///
/// CSPRNG failure is treated as fatal: if `getrandom` itself
/// fails (a rare condition signalling OS-level entropy
/// unavailability), the substrate cannot establish a stable
/// authority identity and the panic surfaces the failure rather
/// than falsifying it with all-zeros.
fn process_authority_id() -> AuthorityId {
    static AUTHORITY_ID: OnceLock<AuthorityId> = OnceLock::new();
    *AUTHORITY_ID.get_or_init(|| {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes)
            .expect("§4.3 authority-id init: OS CSPRNG unavailable");
        AuthorityId::from_bytes(bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::v1::{
        EmitToSyncChannel, ModeratorRead, ScanShard, ViewPrivate,
    };
    use crate::verification::JwtScope;
    use smallvec::{smallvec, SmallVec};

    /// §7.2: when no scope is required, any JWT scope (including
    /// empty) succeeds. Phase 1's v1 capabilities all inherit the
    /// `None` default — pin via `ViewPrivate`.
    #[test]
    fn no_scope_required_succeeds_with_empty_jwt_scope() {
        let empty = JwtScope { scopes: SmallVec::new() };
        check_jwt_scope_for::<ViewPrivate>(&empty).unwrap();
        check_jwt_scope_required(None, &empty).unwrap();
    }

    #[test]
    fn no_scope_required_succeeds_with_arbitrary_jwt_scope() {
        let some = JwtScope {
            scopes: smallvec!["whatever".to_string()],
        };
        check_jwt_scope_for::<ViewPrivate>(&some).unwrap();
        check_jwt_scope_required(None, &some).unwrap();
    }

    /// §7.2: when a capability declares a required scope and the
    /// JWT's scope set contains it, issuance proceeds.
    #[test]
    fn scope_match_succeeds() {
        let granted = JwtScope {
            scopes: smallvec![
                "tools.kryphocron.test.scope".to_string(),
                "tools.kryphocron.other".to_string(),
            ],
        };
        check_jwt_scope_required(Some("tools.kryphocron.test.scope"), &granted).unwrap();
    }

    /// §7.2: when a capability declares a required scope and the
    /// JWT's scope set does NOT contain it, issuance fails with
    /// `AuthDenial::ScopeMismatch`.
    #[test]
    fn scope_mismatch_returns_scope_mismatch() {
        let granted = JwtScope {
            scopes: smallvec!["other.scope".to_string()],
        };
        let err = check_jwt_scope_required(Some("tools.kryphocron.test.scope"), &granted)
            .unwrap_err();
        match err {
            AuthDenial::ScopeMismatch { required, granted: g } => {
                assert_eq!(required, "tools.kryphocron.test.scope");
                assert_eq!(g.as_slice(), &["other.scope"]);
            }
            other => panic!("expected ScopeMismatch, got {other:?}"),
        }
    }

    /// §7.2 empty-is-fail-closed: a capability with a required
    /// scope presented with an empty JWT scope set fails with
    /// `granted: SmallVec::new()`.
    #[test]
    fn empty_scope_against_required_capability_fails_closed() {
        let empty = JwtScope { scopes: SmallVec::new() };
        let err = check_jwt_scope_required(Some("tools.kryphocron.test.scope"), &empty)
            .unwrap_err();
        match err {
            AuthDenial::ScopeMismatch { required, granted } => {
                assert_eq!(required, "tools.kryphocron.test.scope");
                assert!(granted.is_empty());
            }
            other => panic!("expected ScopeMismatch, got {other:?}"),
        }
    }

    /// §7.2 wires `DenialReason::JwtScopeInsufficient` and
    /// `BindOutcomeRepr::DeniedAtPipeline { stage:
    /// PipelineStage::JwtScope, ... }` as the audit-side renderings
    /// of a scope-mismatch denial. The mapping from
    /// `AuthDenial::ScopeMismatch` to those audit shapes lives in
    /// the bind-pipeline path (later Phase 4 sub-phase); this test
    /// pins that the variants exist and are constructible from
    /// outside the audit module.
    #[test]
    fn jwt_scope_insufficient_and_pipeline_stage_jwt_scope_reachable() {
        let _r = DenialReason::JwtScopeInsufficient {
            required: "scope".to_string(),
            granted: SmallVec::new(),
        };
        let _b = BindOutcomeRepr::DeniedAtPipeline {
            stage: PipelineStage::JwtScope,
            reason: DenialReason::JwtScopeInsufficient {
                required: "scope".to_string(),
                granted: SmallVec::new(),
            },
        };
    }

    // ========================================================
    // Phase 7c §4.3 issuance chokepoint tests.
    // ========================================================
    //
    // Coverage matrix (10 scenarios):
    //
    // | Class       | Happy (Did) | Happy (Service) | Anonymous fails | Did fails |
    // | ----------- | ----------- | --------------- | --------------- | --------- |
    // | User        |  ✓          | (covered above) | ✓               | n/a       |
    // | Channel     |  ✓          | (covered above) | ✓               | n/a       |
    // | Substrate   | n/a         | ✓               | ✓               | ✓         |
    // | Moderation  | n/a         | ✓               | ✓               | ✓         |
    //
    // The Service-happy paths for User and Channel are subsumed by
    // Substrate / Moderation happy paths — the same Service requester
    // is admitted for all four classes.

    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use crate::audit::{
        AuditError, ChannelAuditEvent, ChannelAuditSink, CompositeOpId, FallbackAuditEvent,
        FallbackAuditSink, ModerationAuditEvent, ModerationAuditSink, SinkKind,
        SubstrateAuditEvent, SubstrateAuditSink, UserAuditEvent, UserAuditSink,
    };
    use crate::authority::subjects::{
        ChannelBinding, ModerationCaseId, ModerationSubject, ResourceId, ScopeSelector,
        ShardId, ShardRange,
    };
    use crate::identity::{
        KeyId, PublicKey, ServiceIdentity, SessionId, SignatureAlgorithm, TraceId,
    };
    use crate::ingress::{AttributionChain, AuditSinks, OracleSet, RequesterKind};
    use crate::oracle::{
        AudienceOracle, AudienceOracleQuery, AudienceState, BlockOracle, BlockOracleQuery,
        BlockState, MuteOracle, MuteOracleQuery, MuteState,
    };
    use crate::proto::{Did, Nsid, Rkey};

    // ---- No-op sinks/oracles for AuthContext construction ----

    struct NoopUserSink;
    impl UserAuditSink for NoopUserSink {
        fn record(&self, _: UserAuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }
    struct NoopChannelSink;
    impl ChannelAuditSink for NoopChannelSink {
        fn record(&self, _: ChannelAuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }
    struct NoopSubstrateSink;
    impl SubstrateAuditSink for NoopSubstrateSink {
        fn record(&self, _: SubstrateAuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }
    struct NoopModerationSink;
    impl ModerationAuditSink for NoopModerationSink {
        fn record(&self, _: ModerationAuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }
    struct NoopFallback;
    impl FallbackAuditSink for NoopFallback {
        fn record_panic(
            &self,
            _: SinkKind,
            _: TraceId,
            _: crate::authority::capability::CapabilityKind,
            _: SystemTime,
        ) {
        }
        fn record_composite_failure(
            &self,
            _: TraceId,
            _: CompositeOpId,
            _: &[SinkKind],
            _: &[SinkKind],
            _: SystemTime,
        ) {
        }
        fn record_event(&self, _: FallbackAuditEvent) {}
    }

    struct NoopBlockOracle;
    impl BlockOracle for NoopBlockOracle {
        fn block_state(&self, _: &Did, _: &Did) -> BlockState {
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

    // ---- Fixture factories ----

    fn sample_did() -> Did {
        Did::new("did:plc:phase7ctest").unwrap()
    }

    fn sample_service_identity() -> ServiceIdentity {
        ServiceIdentity::new_internal(
            sample_did(),
            KeyId::from_bytes([0u8; 32]),
            PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                bytes: [0u8; 32],
            },
            None,
        )
    }

    fn sample_resource_id() -> ResourceId {
        ResourceId::new(
            sample_did(),
            Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            Rkey::new("3jzfcijpj2z2a").unwrap(),
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
            ShardRange::new(ShardId::from_bytes([0; 8]), ShardId::from_bytes([0xFF; 8]))
                .unwrap(),
        )
    }

    fn sample_moderation_subject() -> ModerationSubject {
        ModerationSubject {
            resource: sample_resource_id(),
            case: ModerationCaseId::from_bytes([0u8; 16]),
        }
    }

    /// Owned bundle: keeps the no-op sinks/oracles alive while the
    /// borrowed [`AuthContext`] is in scope. The `Arc` discipline
    /// is overkill (no sharing across threads in these tests) but
    /// it keeps the fixture self-contained.
    struct ContextFixture {
        _user: Arc<NoopUserSink>,
        _channel: Arc<NoopChannelSink>,
        _substrate: Arc<NoopSubstrateSink>,
        _moderation: Arc<NoopModerationSink>,
        _fallback: Arc<NoopFallback>,
        _inspection: Arc<NoInspectionNotifications>,
        _correlation_key: crate::identity::CorrelationKey,
        _block: Arc<NoopBlockOracle>,
        _audience: Arc<NoopAudienceOracle>,
        _mute: Arc<NoopMuteOracle>,
    }

    impl ContextFixture {
        fn new() -> Self {
            ContextFixture {
                _user: Arc::new(NoopUserSink),
                _channel: Arc::new(NoopChannelSink),
                _substrate: Arc::new(NoopSubstrateSink),
                _moderation: Arc::new(NoopModerationSink),
                _fallback: Arc::new(NoopFallback),
                _inspection: Arc::new(NoInspectionNotifications),
                _correlation_key: crate::identity::CorrelationKey::from_bytes([0u8; 32]),
                _block: Arc::new(NoopBlockOracle),
                _audience: Arc::new(NoopAudienceOracle),
                _mute: Arc::new(NoopMuteOracle),
            }
        }

        fn build_ctx(&self, requester: Requester) -> AuthContext<'_> {
            AuthContext::new_internal(
                requester,
                TraceId::from_bytes([0xAB; 16]),
                AuditSinks {
                    user: &*self._user,
                    channel: &*self._channel,
                    substrate: &*self._substrate,
                    moderation: &*self._moderation,
                    fallback: &*self._fallback,
                    inspection_queue: &*self._inspection,
                    correlation_key: &self._correlation_key,
                },
                OracleSet {
                    block: &*self._block,
                    audience: &*self._audience,
                    mute: &*self._mute,
                },
                AttributionChain::empty(),
                crate::authority::capability::CapabilitySet::empty(),
            )
        }
    }

    // ---- Happy paths (4) ----

    // Proof types do NOT impl Debug (§4.3 forbidden-derives discipline).
    // Tests use `if let Ok(_)` / `if let Err(e)` patterns instead of
    // .unwrap() / .unwrap_err() — the latter trigger Debug bounds.

    /// §4.3 stage 1: user-class issuance with a [`Requester::Did`]
    /// returns a sealed [`UserProof<ViewPrivate>`].
    #[test]
    fn issue_user_succeeds_with_did_requester() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let r = issue_user::<ViewPrivate>(&ctx, sample_resource_id());
        assert!(r.is_ok(), "user-class issuance with Did requester should succeed");
    }

    /// §4.3 stage 1: channel-class issuance with a [`Requester::Did`]
    /// returns a sealed [`ChannelProof<EmitToSyncChannel>`].
    #[test]
    fn issue_channel_succeeds_with_did_requester() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let r = issue_channel::<EmitToSyncChannel>(&ctx, sample_channel_subject());
        assert!(r.is_ok(), "channel-class issuance with Did requester should succeed");
    }

    /// §4.3 stage 1 (§4.6): substrate-class issuance with a
    /// [`Requester::Service`] returns a sealed
    /// [`SubstrateProof<ScanShard>`].
    #[test]
    fn issue_substrate_succeeds_with_service_requester() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let r = issue_substrate::<ScanShard>(&ctx, sample_substrate_subject());
        assert!(r.is_ok(), "substrate-class issuance with Service requester should succeed");
    }

    /// §4.3 stage 1: moderation-class issuance with a
    /// [`Requester::Service`] returns a sealed
    /// [`ModerationProof<ModeratorRead>`].
    #[test]
    fn issue_moderation_succeeds_with_service_requester() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Service(sample_service_identity()));
        let r = issue_moderation::<ModeratorRead>(&ctx, sample_moderation_subject());
        assert!(r.is_ok(), "moderation-class issuance with Service requester should succeed");
    }

    // ---- Anonymous-rejected (4) ----
    //
    // Adversarial: every chokepoint rejects Anonymous at stage 1.
    // The class field on RequesterLacksAuthority must match the
    // chokepoint that denied — forensic clarity per §6.1.

    #[test]
    fn issue_user_rejects_anonymous_at_stage_1() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Anonymous);
        let Err(err) = issue_user::<ViewPrivate>(&ctx, sample_resource_id()) else {
            panic!("expected Err, got Ok");
        };
        match err {
            AuthDenial::RequesterLacksAuthority { class, found } => {
                assert_eq!(class, CapabilityClass::User);
                assert_eq!(found, RequesterKind::Anonymous);
            }
            other => panic!("expected RequesterLacksAuthority(User, Anonymous), got {other:?}"),
        }
    }

    #[test]
    fn issue_channel_rejects_anonymous_at_stage_1() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Anonymous);
        let Err(err) = issue_channel::<EmitToSyncChannel>(&ctx, sample_channel_subject())
        else {
            panic!("expected Err, got Ok");
        };
        match err {
            AuthDenial::RequesterLacksAuthority { class, found } => {
                assert_eq!(class, CapabilityClass::Channel);
                assert_eq!(found, RequesterKind::Anonymous);
            }
            other => panic!(
                "expected RequesterLacksAuthority(Channel, Anonymous), got {other:?}"
            ),
        }
    }

    #[test]
    fn issue_substrate_rejects_anonymous_at_stage_1() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Anonymous);
        let Err(err) = issue_substrate::<ScanShard>(&ctx, sample_substrate_subject()) else {
            panic!("expected Err, got Ok");
        };
        match err {
            AuthDenial::RequesterLacksAuthority { class, found } => {
                assert_eq!(class, CapabilityClass::Substrate);
                assert_eq!(found, RequesterKind::Anonymous);
            }
            other => panic!(
                "expected RequesterLacksAuthority(Substrate, Anonymous), got {other:?}"
            ),
        }
    }

    #[test]
    fn issue_moderation_rejects_anonymous_at_stage_1() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Anonymous);
        let Err(err) =
            issue_moderation::<ModeratorRead>(&ctx, sample_moderation_subject())
        else {
            panic!("expected Err, got Ok");
        };
        match err {
            AuthDenial::RequesterLacksAuthority { class, found } => {
                assert_eq!(class, CapabilityClass::Moderation);
                assert_eq!(found, RequesterKind::Anonymous);
            }
            other => panic!(
                "expected RequesterLacksAuthority(Moderation, Anonymous), got {other:?}"
            ),
        }
    }

    // ---- Did-rejected for substrate / moderation (2) ----
    //
    // Adversarial: §4.6 read-everything-authority and §4.3
    // moderation-as-service both forbid Did requesters. Failure
    // surfaces at stage 1 — NOT stage 3 (proof construction).
    // Stage matters: if a Did requester reached stage 3 and only
    // failed there, the surface would have been broken (a
    // SubstrateProof should never exist in a function that took
    // a Did requester).

    #[test]
    fn issue_substrate_rejects_did_at_stage_1_per_4_6() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let Err(err) = issue_substrate::<ScanShard>(&ctx, sample_substrate_subject()) else {
            panic!("expected Err, got Ok");
        };
        match err {
            AuthDenial::RequesterLacksAuthority { class, found } => {
                assert_eq!(class, CapabilityClass::Substrate);
                assert_eq!(found, RequesterKind::Did);
            }
            other => panic!(
                "expected RequesterLacksAuthority(Substrate, Did) per §4.6 read-everything-authority, got {other:?}"
            ),
        }
    }

    #[test]
    fn issue_moderation_rejects_did_at_stage_1_per_moderation_as_service() {
        let fixture = ContextFixture::new();
        let ctx = fixture.build_ctx(Requester::Did(sample_did()));
        let Err(err) =
            issue_moderation::<ModeratorRead>(&ctx, sample_moderation_subject())
        else {
            panic!("expected Err, got Ok");
        };
        match err {
            AuthDenial::RequesterLacksAuthority { class, found } => {
                assert_eq!(class, CapabilityClass::Moderation);
                assert_eq!(found, RequesterKind::Did);
            }
            other => panic!(
                "expected RequesterLacksAuthority(Moderation, Did) per §4.3 moderation-as-service, got {other:?}"
            ),
        }
    }

    // ---- AuthorityId stability (1) ----

    /// `process_authority_id` returns the same id across calls
    /// within the same process (§4.3 "authority module instance"
    /// framing). OnceLock initialization is exercised by the first
    /// call from any of the issuance tests above; this test simply
    /// pins the per-process stability.
    #[test]
    fn process_authority_id_is_stable_within_process() {
        let a = process_authority_id();
        let b = process_authority_id();
        assert_eq!(a, b, "process_authority_id must be process-static");
    }

    // ========================================================
    // Phase 7d §4.3 stage 0 deprecation-gate tests.
    // ========================================================

    /// §4.3 stage 0 (§5.6): an Active lexicon NSID passes the
    /// gate. `tools.kryphocron.feed.postPrivate` is in the v1
    /// registry as Active.
    #[test]
    fn stage_0_active_lexicon_passes() {
        let nsid = Nsid::new("tools.kryphocron.feed.postPrivate").unwrap();
        let r = check_stage_0_deprecation(&nsid, 0);
        assert!(matches!(r, Ok(())));
    }

    /// §4.3 stage 0: an NSID outside the closed-namespace registry
    /// passes — the registry is authoritative for v1 lexicons; non-
    /// v1 NSIDs aren't gated by §5.6 (they're caught earlier in
    /// the type system or surface as predicate-stage failures).
    #[test]
    fn stage_0_unknown_nsid_passes() {
        let nsid = Nsid::new("com.example.unknown").unwrap();
        let r = check_stage_0_deprecation(&nsid, 0);
        assert!(matches!(r, Ok(())));
    }
}
