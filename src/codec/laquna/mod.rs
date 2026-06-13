// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Laquna — the substrate's default at-rest content codec (rev 3 §3).
//!
//! kryphocron deployments encode private-tier record content at rest via
//! this codec by default (the constitutional encoding-at-default floor, rev
//! 3 §1 / §2.1). Laquna is a deterministic, reversible **friction** transform
//! — opacity against opportunistic, at-scale content extraction. It is **not
//! encryption**: it provides no confidentiality, authentication, or
//! resistance to a motivated adversary (the decoder ships in this crate and
//! the per-record seed is derived from public metadata). Operators needing
//! stronger guarantees substitute a strengthening codec via
//! `DefaultAtRestHooksBuilder::with_codec` (rev 3 §5.1 / §5.5).
//!
//! The encoding *mechanics* are the vendored laquna v0.2.0 source in
//! `internal`; this module is the [`ContentCodec`] adapter that bridges
//! laquna's stateless sync free functions to the substrate's stateful async
//! trait, deriving the per-record seed from the record-identity tuple and
//! recovering the rotation slug from the rotation oracle's generation mark.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::encryption::{
    CodecError, CodecId, ContentCodec, DecodeContext, EncodeContext, EncodedRecord,
    RotationContext, RotationGenerationMark, RotationOracle,
};
use crate::proto::{Did, Nsid, RecordKey};

/// Default rotation cadence: 24-hour wall-clock (rev 3 §4.2).
const DEFAULT_CADENCE: Duration = Duration::from_secs(86_400);

mod internal;
pub use internal::DecodeError;

/// The default kryphocron at-rest content codec.
///
/// Construction:
/// - [`Codec::default`] — recommended; uses the `{originator}||{nsid}||{rkey}`
///   seed-derivation recipe (§3.3).
/// - [`Codec::new`] — custom seed-derivation policy for operators with
///   non-default deployment constraints.
///
/// Stateful only in the configured seed-derivation policy; no per-encode
/// mutable state.
#[derive(Clone)]
pub struct Codec {
    seed_policy: SeedPolicy,
}

/// Seed-derivation policy. The substrate computes the per-record seed by
/// applying this policy to the [`EncodeContext`] / [`DecodeContext`]. The
/// default policy concatenates the originator DID, NSID, and rkey separated
/// by `||`.
#[derive(Clone)]
pub enum SeedPolicy {
    /// `{originator}||{nsid}||{rkey}` — default; per-record uniqueness via the
    /// substrate's record-identity tuple (the three identity components rev 6's
    /// [`EncodeContext`] / [`DecodeContext`] already carry as separate fields).
    DidNsidRkey,

    /// Operator-supplied closure for custom recipes. The closure receives the
    /// full [`EncodeContext`] reference and returns the seed bytes. The
    /// substrate enforces the "non-empty seed" precondition before calling
    /// laquna (via `debug_assert!` — see §3.3).
    ///
    /// The closure operates on `&EncodeContext` directly rather than a derived
    /// projection (rev 3 deliberately introduces no new public `RecordIdentity`
    /// type — §10). On the decode side the adapter synthesizes an equivalent
    /// `EncodeContext` from the [`DecodeContext`]'s matching identity fields
    /// (with `current_generation_hint: None`, since decode reads the slug from
    /// the stored artifact, not the oracle).
    //
    // The inline closure type is the rev 3 §3.2 surface verbatim; a `type`
    // alias would be new public API (§10 admits only
    // `RotationOracleConstructionError`), so the complexity lint is allowed
    // locally rather than factored out into a public alias.
    #[allow(clippy::type_complexity)]
    Custom(Arc<dyn Fn(&EncodeContext) -> Vec<u8> + Send + Sync>),
}

impl Default for Codec {
    fn default() -> Self {
        Self {
            seed_policy: SeedPolicy::DidNsidRkey,
        }
    }
}

impl Codec {
    /// Construct a codec with a custom [`SeedPolicy`].
    #[must_use]
    pub fn new(seed_policy: SeedPolicy) -> Self {
        Self { seed_policy }
    }
}

// `SeedPolicy::Custom` holds a closure (not `Debug`); hand-write `Debug` so
// `Codec` stays diagnostic-printable without exposing the closure.
impl std::fmt::Debug for Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Codec")
            .field("seed_policy", &self.seed_policy)
            .finish()
    }
}

impl std::fmt::Debug for SeedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedPolicy::DidNsidRkey => f.write_str("DidNsidRkey"),
            SeedPolicy::Custom(_) => f.write_str("Custom(<closure>)"),
        }
    }
}

/// The default seed recipe: ASCII `{originator}||{nsid}||{rkey}` (§3.3).
///
/// Takes the three identity components directly so the same recipe serves both
/// the encode (`EncodeContext`) and decode (`DecodeContext`) sides. Output is
/// non-empty by ATProto identity rules (the three components are non-empty);
/// the caller `debug_assert!`s this defensively.
fn derive_seed_did_nsid_rkey(originator: &Did, nsid: &Nsid, rkey: &RecordKey) -> Vec<u8> {
    format!("{}||{}||{}", originator.as_str(), nsid.as_str(), rkey.as_str()).into_bytes()
}

/// Project a [`DecodeContext`] into an equivalent [`EncodeContext`] for
/// `SeedPolicy::Custom` decode-side seed derivation (rev 3 §3.4 Option 1).
///
/// Copies the four identity fields plus `trace_id` / `operator_context`;
/// `current_generation_hint` is `None` because decode recovers the slug from
/// the stored artifact's tail, not from the rotation oracle.
fn decode_ctx_as_encode_ctx(ctx: &DecodeContext) -> EncodeContext {
    EncodeContext {
        nsid: ctx.nsid.clone(),
        rkey: ctx.rkey.clone(),
        originator: ctx.originator.clone(),
        audience_list: ctx.audience_list.clone(),
        current_generation_hint: None,
        trace_id: ctx.trace_id,
        operator_context: ctx.operator_context.clone(),
    }
}

/// Parse the 32-byte rotation slug from a [`RotationGenerationMark`].
///
/// Internal to the laquna adapter — adds no public method on
/// `RotationGenerationMark`. Parses the mark format committed by the default
/// rotation oracle (§4.7): `"laquna/{:020}/{hex64}"`. Returns `None` on any
/// malformed input; the caller treats `None` as a substrate-invariant
/// violation (`expect`), since the default oracle always produces this shape.
fn parse_slug_from_mark(mark: &RotationGenerationMark) -> Option<[u8; 32]> {
    let s: &str = mark.as_str();
    // Expect ["laquna", "<unix_secs>", "<hex_slug>"].
    let mut parts = s.splitn(3, '/');
    let prefix = parts.next()?;
    let _unix_secs = parts.next()?; // present for lex ordering; only the slug is needed here
    let hex_slug = parts.next()?;
    if prefix != "laquna" || hex_slug.len() != 64 {
        return None;
    }
    let mut slug = [0u8; 32];
    hex::decode_to_slice(hex_slug, &mut slug).ok()?;
    Some(slug)
}

#[async_trait]
impl ContentCodec for Codec {
    fn codec_id(&self) -> CodecId {
        // Stable for the lifetime of records encoded under it (§3.6). Future
        // byte-compatible laquna-internals bumps keep `"laquna/0.2"`.
        CodecId::new("laquna/0.2").expect("\"laquna/0.2\" is a valid codec id")
    }

    fn requires_rotation(&self) -> bool {
        // The slug is laquna's rotation-batch identifier; friction degrades
        // when one slug stamps many records (§3.5). The install seam
        // fail-closes if no rotation oracle is installed.
        true
    }

    async fn encode(
        &self,
        plaintext: &[u8],
        context: &EncodeContext,
        _deadline: Instant,
    ) -> Result<Vec<u8>, CodecError> {
        let seed = match &self.seed_policy {
            SeedPolicy::DidNsidRkey => {
                derive_seed_did_nsid_rkey(&context.originator, &context.nsid, &context.rkey)
            }
            SeedPolicy::Custom(f) => f(context),
        };
        // Substrate invariant: non-empty under `DidNsidRkey` (ATProto rules)
        // and under `Custom` (operator-supplied contract). An empty seed is an
        // invariant violation, not a runtime condition — no new `CodecError`
        // variant (§3.4 error-variant policy).
        debug_assert!(
            !seed.is_empty(),
            "substrate invariant: seed must be non-empty"
        );

        // The rotation generation is sourced by the substrate from the
        // installed oracle and already freshness-checked. The install seam
        // (`validate_at_rest_install`) probes that the oracle yields a
        // generation, so under a validated install the hint is `Some`. A `None`
        // here is the runtime-transient case (an oracle healthy at install
        // returns `None` later — backend unavailability, cold cache, rate
        // limit): return a clean, fail-closed error rather than panicking.
        let mark = context.current_generation_hint.as_ref().ok_or_else(|| {
            CodecError::RotationStateUnavailable {
                codec: self.codec_id(),
            }
        })?;
        // A mark that fails to parse, by contrast, is a deliberate operator
        // configuration error — pairing laquna's codec with an oracle that
        // emits a non-laquna mark format (§4.7) — not a runtime transient.
        // That stays a substrate-invariant panic.
        let slug = parse_slug_from_mark(mark).expect(
            "substrate invariant: rotation mark must match the default \
             oracle's format (§4.7)",
        );

        // Laquna's encode is sync + CPU-bound (zstd). At typical record sizes
        // (a few KB) the blocking compression is microseconds; ~1MB lexicon
        // upper-bound records compress in low single-digit ms — within
        // async-runtime expectations, so no spawn_blocking. The deadline is
        // accepted but unused.
        Ok(internal::encode(plaintext, &seed, &slug))
    }

    async fn decode(
        &self,
        encoded: &EncodedRecord,
        context: &DecodeContext,
        _deadline: Instant,
    ) -> Result<Vec<u8>, CodecError> {
        // Decode-side seed derivation projects the same identity fields. The
        // slug is read from the stored artifact's tail by laquna's decoder, so
        // no rotation mark is needed here.
        let seed = match &self.seed_policy {
            SeedPolicy::DidNsidRkey => {
                derive_seed_did_nsid_rkey(&context.originator, &context.nsid, &context.rkey)
            }
            SeedPolicy::Custom(f) => f(&decode_ctx_as_encode_ctx(context)),
        };
        debug_assert!(
            !seed.is_empty(),
            "substrate invariant: seed must be non-empty"
        );

        // Decode failure maps to the existing rev-6 `CodecError::Malformed`
        // (wrong seed, wrong slug, or corruption). The laquna-side `DecodeError`
        // carries no detail by design; the adapter introduces no
        // `DecodeFailed(String)` variant (§3.4).
        internal::decode(&encoded.content, &seed)
            .map_err(|_e| CodecError::Malformed {
                codec: self.codec_id(),
            })
    }
}

// ===========================================================================
// DefaultRotationOracle (rev 3 §4) — the single-process starter rotation
// oracle shipped with the laquna default codec.
// ===========================================================================

/// Error returned when [`DefaultRotationOracle`] construction fails.
///
/// A *construction-time* error, distinct from the runtime behavior the oracle
/// exposes through the [`RotationOracle`] trait during operation. The two
/// cases are a CSRNG failure (no initial slug could be generated) and an
/// install-time persistence-write failure (the write check at
/// `<data_dir>/kryphocron/rotation.state` failed). Surfacing the latter at
/// construction lets operators see a misconfigured data directory at the
/// diagnosable install point rather than at the first runtime rotation
/// (rev 3 §4.5 / §4.7). This is the only new public type the default-codec
/// arc introduces (rev 3 §10).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RotationOracleConstructionError {
    /// The CSRNG returned an error during initial slug generation.
    #[error("CSRNG failed during initial rotation-slug generation: {0}")]
    CsrngFailed(getrandom::Error),
    /// The install-time write check at `<data_dir>/kryphocron/rotation.state`
    /// failed (e.g. a non-writable data directory).
    #[error("install-time rotation-state write failed at {path}: {source}")]
    InitialPersistenceFailed {
        /// The persistence path the write was attempted at.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
}

/// The current rotation slug and the wall-clock instant it was generated.
struct RotationState {
    current_slug: [u8; 32],
    generated_at: SystemTime,
}

/// A request to persist a rotation state, dispatched to the background
/// persistence worker on rotation (rev 3 §4.6).
struct PersistRequest {
    slug: [u8; 32],
    generated_at: SystemTime,
}

/// The default [`RotationOracle`] for kryphocron's built-in laquna codec
/// (rev 3 §4).
///
/// **Single-process deployments only** (rev 3 §4.1). The slug + its generation
/// timestamp live in-memory behind an `RwLock` and are persisted to
/// `<data_dir>/kryphocron/rotation.state`; the in-memory state is the
/// authoritative source, so this oracle is never stale relative to external
/// storage (its [`data_freshness_bound`](RotationOracle::data_freshness_bound)
/// is [`Duration::MAX`]). Multi-process deployments — anything behind a load
/// balancer, with separate writer/reader processes, or with maintenance
/// workers — substitute a coordinated `RotationOracle` (DB-backed, KMS-backed,
/// etc.) from day one to keep rotation cadence correct across processes.
///
/// Rotation is wall-clock: a fresh CSRNG slug is generated when the configured
/// cadence (default 24h) elapses past the current slug's generation time.
/// Rotation does the in-memory swap synchronously and dispatches the file
/// write to a background thread (rev 3 §4.6), so a slow filesystem does not
/// stall encode calls.
pub struct DefaultRotationOracle {
    state: Arc<RwLock<RotationState>>,
    cadence: Duration,
    persist_tx: mpsc::Sender<PersistRequest>,
}

impl DefaultRotationOracle {
    /// Construct with the default 24-hour wall-clock cadence, persisting to
    /// `<data_dir>/kryphocron/rotation.state`.
    ///
    /// Performs an install-time write check at the persistence path, so a
    /// misconfigured data directory surfaces here rather than at the first
    /// runtime rotation.
    ///
    /// # Errors
    ///
    /// [`RotationOracleConstructionError`] on CSRNG failure or install-time
    /// persistence-write failure.
    pub fn for_data_dir(data_dir: PathBuf) -> Result<Self, RotationOracleConstructionError> {
        Self::construct(default_state_path(&data_dir), DEFAULT_CADENCE)
    }

    /// Builder for operators tuning cadence, persistence path, or both.
    #[must_use]
    pub fn builder() -> DefaultRotationOracleBuilder {
        DefaultRotationOracleBuilder {
            cadence: DEFAULT_CADENCE,
            persistence_path: None,
        }
    }

    fn construct(
        persistence_path: PathBuf,
        cadence: Duration,
    ) -> Result<Self, RotationOracleConstructionError> {
        let now = SystemTime::now();

        // Restart behavior (§4.4): load existing state if present + parseable +
        // still within cadence; otherwise generate a fresh slug.
        let state = match read_state_file(&persistence_path) {
            Some(loaded)
                if now
                    .duration_since(loaded.generated_at)
                    .map(|age| age < cadence)
                    .unwrap_or(false) =>
            {
                loaded
            }
            _ => RotationState {
                current_slug: generate_slug()
                    .map_err(RotationOracleConstructionError::CsrngFailed)?,
                generated_at: now,
            },
        };

        // Install-time write check (§4.5 / §4.7 R2 #9).
        write_state_file(&persistence_path, &state).map_err(|source| {
            RotationOracleConstructionError::InitialPersistenceFailed {
                path: persistence_path.clone(),
                source,
            }
        })?;

        // Background persistence worker (§4.6): runtime rotation writes are
        // dispatched here so a slow fsync never stalls an encode. Best-effort —
        // transient write failures are tolerated (the install-time check above
        // catches persistent misconfig; restart behavior (§4.4) handles a
        // crash mid-write). The worker exits when the oracle drops (the sender
        // disconnects).
        let (persist_tx, persist_rx) = mpsc::channel::<PersistRequest>();
        let worker_path = persistence_path;
        std::thread::spawn(move || {
            while let Ok(req) = persist_rx.recv() {
                let snapshot = RotationState {
                    current_slug: req.slug,
                    generated_at: req.generated_at,
                };
                let _ = write_state_file(&worker_path, &snapshot);
            }
        });

        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            cadence,
            persist_tx,
        })
    }
}

/// Builder for [`DefaultRotationOracle`] (rev 3 §4.5).
pub struct DefaultRotationOracleBuilder {
    cadence: Duration,
    persistence_path: Option<PathBuf>,
}

impl DefaultRotationOracleBuilder {
    /// Set the rotation cadence (default 24h).
    #[must_use]
    pub fn cadence(mut self, cadence: Duration) -> Self {
        self.cadence = cadence;
        self
    }

    /// Set the persistence path (e.g. `data_dir.join("kryphocron/rotation.state")`).
    /// Required — `build()` fails if unset.
    #[must_use]
    pub fn persistence_path(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path);
        self
    }

    /// Build the oracle.
    ///
    /// # Errors
    ///
    /// [`RotationOracleConstructionError`] on CSRNG failure, install-time
    /// persistence-write failure, or if `persistence_path` was never set
    /// (reported as `InitialPersistenceFailed` with an empty path — the
    /// builder has no `data_dir` to default it from, unlike
    /// [`DefaultRotationOracle::for_data_dir`]).
    pub fn build(self) -> Result<DefaultRotationOracle, RotationOracleConstructionError> {
        let path = self.persistence_path.ok_or_else(|| {
            RotationOracleConstructionError::InitialPersistenceFailed {
                path: PathBuf::new(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "persistence_path must be set on DefaultRotationOracle::builder()",
                ),
            }
        })?;
        DefaultRotationOracle::construct(path, self.cadence)
    }
}

impl RotationOracle for DefaultRotationOracle {
    fn current_generation(&self, _ctx: &RotationContext) -> Option<RotationGenerationMark> {
        let now = SystemTime::now();

        // Fast path: read-lock; if the current slug is within cadence, serve it.
        {
            let st = self.state.read().expect("rotation state lock not poisoned");
            let fresh = now
                .duration_since(st.generated_at)
                .map(|age| age < self.cadence)
                .unwrap_or(false);
            if fresh {
                return Some(format_mark(st.generated_at, &st.current_slug));
            }
        }

        // Rotation path: write-lock + double-check (another thread may have
        // rotated between the read and write locks).
        let mut st = self.state.write().expect("rotation state lock not poisoned");
        let still_stale = now
            .duration_since(st.generated_at)
            .map(|age| age >= self.cadence)
            .unwrap_or(true);
        if still_stale {
            match generate_slug() {
                Ok(slug) => {
                    st.current_slug = slug;
                    st.generated_at = now;
                    // Dispatch the persist to the background worker (best-effort).
                    let _ = self.persist_tx.send(PersistRequest {
                        slug,
                        generated_at: now,
                    });
                }
                Err(_) => {
                    // Runtime CSRNG failure (rare/transient): keep the current
                    // slug rather than fail the encode. The next query retries.
                }
            }
        }
        Some(format_mark(st.generated_at, &st.current_slug))
    }

    fn last_synced_at(&self) -> SystemTime {
        // The in-memory state is authoritative; report when the current slug
        // was generated (always in the past). Paired with a `Duration::MAX`
        // freshness bound, the §4.6 freshness check never trips for this
        // single-process oracle.
        self.state
            .read()
            .expect("rotation state lock not poisoned")
            .generated_at
    }

    fn data_freshness_bound(&self) -> Duration {
        // Single-process authoritative oracle: never stale relative to external
        // storage (mirrors `NoRotationOracle`). Multi-process deployments
        // substitute a coordinated oracle with a real freshness bound.
        Duration::MAX
    }
}

/// `<data_dir>/kryphocron/rotation.state` (rev 3 §4.4).
fn default_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("kryphocron").join("rotation.state")
}

/// Generate a fresh 32-byte slug from the OS CSRNG (rev 3 §4.3).
fn generate_slug() -> Result<[u8; 32], getrandom::Error> {
    let mut slug = [0u8; 32];
    getrandom::getrandom(&mut slug)?;
    Ok(slug)
}

/// Format the lex-sortable rotation mark (rev 3 §4.7):
/// `"laquna/{:020}/{hex64}"` — 92 chars, within `BoundedString<128>`.
fn format_mark(generated_at: SystemTime, slug: &[u8; 32]) -> RotationGenerationMark {
    let unix_secs = generated_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    RotationGenerationMark::new(format!("laquna/{:020}/{}", unix_secs, hex::encode(slug)))
        .expect("rotation mark (92 bytes) fits BoundedString<128>")
}

/// Read persisted rotation state. Returns `None` on any failure (missing,
/// unreadable, or unparseable) — the caller then starts a fresh batch (§4.4).
fn read_state_file(path: &Path) -> Option<RotationState> {
    let contents = std::fs::read_to_string(path).ok()?;
    let mut lines = contents.lines();
    let secs: u64 = lines.next()?.trim().parse().ok()?;
    let hex_slug = lines.next()?.trim();
    if hex_slug.len() != 64 {
        return None;
    }
    let mut slug = [0u8; 32];
    hex::decode_to_slice(hex_slug, &mut slug).ok()?;
    Some(RotationState {
        current_slug: slug,
        generated_at: UNIX_EPOCH + Duration::from_secs(secs),
    })
}

/// Persist rotation state as two lines: `<unix_secs>\n<hex_slug>\n`, creating
/// the parent directory if needed.
fn write_state_file(path: &Path, state: &RotationState) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let secs = state
        .generated_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    std::fs::write(
        path,
        format!("{}\n{}\n", secs, hex::encode(state.current_slug)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TraceId;

    fn mark_with_slug(slug: [u8; 32]) -> RotationGenerationMark {
        // The default oracle's §4.7 format: "laquna/{:020}/{hex64}".
        RotationGenerationMark::new(format!(
            "laquna/{:020}/{}",
            1_700_000_000u64,
            hex::encode(slug)
        ))
        .expect("mark fits the BoundedString bound")
    }

    fn enc_ctx(rkey: &str, mark: RotationGenerationMark) -> EncodeContext {
        EncodeContext {
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            rkey: RecordKey::new(rkey).unwrap(),
            originator: Did::new("did:plc:exampleexampleexample").unwrap(),
            audience_list: None,
            current_generation_hint: Some(mark),
            trace_id: TraceId::from_bytes([0xAB; 16]),
            operator_context: Default::default(),
        }
    }

    fn dec_ctx(rkey: &str) -> DecodeContext {
        DecodeContext {
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            rkey: RecordKey::new(rkey).unwrap(),
            originator: Did::new("did:plc:exampleexampleexample").unwrap(),
            audience_list: None,
            trace_id: TraceId::from_bytes([0xAB; 16]),
            operator_context: Default::default(),
        }
    }

    /// The default codec round-trips: encode then decode recovers the
    /// plaintext, and the encoded bytes are not the plaintext.
    #[tokio::test]
    async fn default_codec_round_trips() {
        let codec = Codec::default();
        let mark = mark_with_slug([0x5a; 32]);
        let plaintext = b"a private post body";
        let deadline = Instant::now();

        let content = codec
            .encode(plaintext, &enc_ctx("3kabcdefghij2", mark.clone()), deadline)
            .await
            .expect("encode succeeds");
        assert_ne!(content.as_slice(), plaintext.as_slice(), "encoded bytes are not plaintext");

        let record = EncodedRecord {
            codec: codec.codec_id(),
            content,
            generation: Some(mark),
        };
        let recovered = codec
            .decode(&record, &dec_ctx("3kabcdefghij2"), deadline)
            .await
            .expect("decode succeeds");
        assert_eq!(recovered, plaintext);
    }

    /// Decoding with a different record-identity seed (different rkey →
    /// different derived seed) fails closed as `Malformed`.
    #[tokio::test]
    async fn decode_with_wrong_identity_seed_is_malformed() {
        let codec = Codec::default();
        let mark = mark_with_slug([0x5a; 32]);
        let deadline = Instant::now();
        let content = codec
            .encode(b"secret", &enc_ctx("3kabcdefghij2", mark.clone()), deadline)
            .await
            .unwrap();
        let record = EncodedRecord {
            codec: codec.codec_id(),
            content,
            generation: Some(mark),
        };
        let err = codec
            .decode(&record, &dec_ctx("3kabcdefghij3"), deadline)
            .await
            .unwrap_err();
        assert!(matches!(err, CodecError::Malformed { .. }));
    }

    /// Rotation-absent runtime-transient case: an oracle healthy at install returns
    /// `None` later, so the encode-time `current_generation_hint` is `None`.
    /// The adapter returns a clean fail-closed `RotationStateUnavailable`
    /// rather than panicking.
    #[tokio::test]
    async fn encode_returns_rotation_unavailable_on_none_hint() {
        let codec = Codec::default();
        let ctx = EncodeContext {
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            rkey: RecordKey::new("3kabcdefghij2").unwrap(),
            originator: Did::new("did:plc:exampleexampleexample").unwrap(),
            audience_list: None,
            current_generation_hint: None,
            trace_id: TraceId::from_bytes([0xAB; 16]),
            operator_context: Default::default(),
        };
        let err = codec.encode(b"x", &ctx, Instant::now()).await.unwrap_err();
        assert!(matches!(err, CodecError::RotationStateUnavailable { .. }));
    }

    #[test]
    fn codec_id_is_laquna_0_2() {
        assert_eq!(Codec::default().codec_id().as_str(), "laquna/0.2");
    }

    #[test]
    fn requires_rotation_is_true() {
        assert!(Codec::default().requires_rotation());
    }

    // ---- DefaultRotationOracle (rev 3 §4) ----

    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_tmp_dir() -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kryphocron-rot-{}-{}", std::process::id(), n))
    }

    fn rot_ctx() -> RotationContext {
        RotationContext {
            originator: Did::new("did:plc:exampleexampleexample").unwrap(),
            nsid: Nsid::new("tools.kryphocron.feed.postPrivate").unwrap(),
            audience_list: None,
        }
    }

    #[test]
    fn oracle_for_data_dir_constructs_and_serves_mark() {
        let dir = unique_tmp_dir();
        let oracle = DefaultRotationOracle::for_data_dir(dir.clone()).expect("construct");
        let mark = oracle.current_generation(&rot_ctx()).expect("serves a mark");
        assert!(mark.as_str().starts_with("laquna/"), "mark uses the §4.7 format");
        assert!(
            dir.join("kryphocron").join("rotation.state").exists(),
            "install-time write created the state file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oracle_construction_fails_install_time_on_unwritable_path() {
        // A data_dir that is actually a FILE: create_dir_all of the
        // `<file>/kryphocron` subpath fails (ENOTDIR) at the install-time check.
        let file_as_dir = unique_tmp_dir();
        std::fs::write(&file_as_dir, b"i am a file, not a directory").unwrap();
        let result = DefaultRotationOracle::for_data_dir(file_as_dir.clone());
        assert!(matches!(
            result,
            Err(RotationOracleConstructionError::InitialPersistenceFailed { .. })
        ));
        let _ = std::fs::remove_file(&file_as_dir);
    }

    #[test]
    fn oracle_restart_preserves_slug_within_cadence() {
        let dir = unique_tmp_dir();
        let m1 = {
            let o1 = DefaultRotationOracle::for_data_dir(dir.clone()).unwrap();
            o1.current_generation(&rot_ctx()).unwrap()
        };
        // Reconstruct against the same dir; cadence (24h) has not elapsed.
        let o2 = DefaultRotationOracle::for_data_dir(dir.clone()).unwrap();
        let m2 = o2.current_generation(&rot_ctx()).unwrap();
        assert_eq!(m1, m2, "restart within cadence preserves slug + generation");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oracle_restart_rotates_when_state_stale() {
        let dir = unique_tmp_dir();
        let state_path = dir.join("kryphocron").join("rotation.state");
        std::fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        // Seed a stale state file dated at the unix epoch (1970 ≫ cadence ago).
        std::fs::write(&state_path, format!("0\n{}\n", hex::encode([0x11u8; 32]))).unwrap();
        let stale_mark = format_mark(UNIX_EPOCH, &[0x11u8; 32]);

        let oracle = DefaultRotationOracle::for_data_dir(dir.clone()).unwrap();
        let mark = oracle.current_generation(&rot_ctx()).unwrap();
        assert_ne!(mark, stale_mark, "stale on-disk state rotates to a fresh slug");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_format_is_lex_sortable() {
        let slug = [0xABu8; 32];
        let m1 = format_mark(UNIX_EPOCH + Duration::from_secs(1_000_000), &slug);
        let m2 = format_mark(UNIX_EPOCH + Duration::from_secs(2_000_000), &slug);
        assert!(
            m1.as_str() < m2.as_str(),
            "earlier generation lex-sorts before later (rev 3 §4.7)"
        );
        assert_eq!(m1.as_str().len(), 92, "mark is 92 chars (within BoundedString<128>)");
    }

    #[test]
    fn builder_requires_persistence_path() {
        let result = DefaultRotationOracle::builder().build();
        assert!(matches!(
            result,
            Err(RotationOracleConstructionError::InitialPersistenceFailed { .. })
        ));
    }

    #[test]
    fn builder_custom_cadence_constructs() {
        let dir = unique_tmp_dir();
        let oracle = DefaultRotationOracle::builder()
            .cadence(Duration::from_secs(3600))
            .persistence_path(dir.join("kryphocron").join("rotation.state"))
            .build()
            .unwrap();
        assert!(oracle.current_generation(&rot_ctx()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
