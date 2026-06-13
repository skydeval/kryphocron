// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Vendored from laquna v0.2.0 (github.com/skydeval/laquna, MPL-2.0) per
// rev 3 §3.1 — verbatim modulo crate-attribute/feature-gate stripping and
// crate:: path rebasing. See internal/mod.rs for the full vendoring note.
//! Network stream generator (component stream C).
//!
//! The load-bearing novel component: a parameterized state-iteration network that
//! evolves a 64-byte working state through repeated substitute-diffuse-permute passes,
//! emitting the state as stream bytes. Its parameters — a per-pass substitution table,
//! a per-pass position permutation, the diffuse offset, and the initial state — are all
//! derived from the network material. See `lib.rs` for how this stream is consumed.

use alloc::vec::Vec;

use super::super::materials::Material;

/// Working-state width, in bytes.
const WIDTH: usize = 64;

/// Number of passes applied per emitted block.
const PASSES: usize = 8;

/// Generator for the network stream.
pub(crate) struct NetworkGenerator {
    /// One substitution table per pass.
    substitutions: [[u8; 256]; PASSES],
    /// One position permutation per pass.
    permutations: [[u8; WIDTH]; PASSES],
    /// Diffuse offset: an odd value in `[3, 63]`, fixed for this generator and so
    /// coprime with the width — every position eventually reaches every other.
    offset: usize,
    /// The evolving working state.
    state: [u8; WIDTH],
    /// The most recently emitted block and a cursor into it, so that `produce` can
    /// serve requests that do not align to the block width.
    block: [u8; WIDTH],
    cursor: usize,
}

impl NetworkGenerator {
    /// Build a generator from the schedule and initial state derived from the material.
    pub(crate) fn new(material: &Material) -> Self {
        let schedule = derive_schedule(material);
        NetworkGenerator {
            substitutions: schedule.substitutions,
            permutations: schedule.permutations,
            offset: schedule.offset,
            state: schedule.initial_state,
            block: [0u8; WIDTH],
            cursor: WIDTH, // start empty, so the first `produce` refills
        }
    }

    /// Emit the next `length` bytes of the network stream.
    pub(crate) fn produce(&mut self, length: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(length);
        while out.len() < length {
            if self.cursor == WIDTH {
                self.refill_block();
            }
            let take = (length - out.len()).min(WIDTH - self.cursor);
            out.extend_from_slice(&self.block[self.cursor..self.cursor + take]);
            self.cursor += take;
        }
        out
    }

    /// Run one full block of passes over the working state, then capture the state as
    /// the next block of output.
    fn refill_block(&mut self) {
        for pass in 0..PASSES {
            apply_pass(
                &mut self.state,
                &self.substitutions[pass],
                &self.permutations[pass],
                self.offset,
            );
        }
        self.block = self.state;
        self.cursor = 0;
    }
}

/// The derived parameters and initial state for one material: everything `new` needs
/// to stand up a generator. Factored out of `new` so the testing surface can read the
/// same derivation without duplicating it.
pub(crate) struct Schedule {
    pub(crate) substitutions: [[u8; 256]; PASSES],
    pub(crate) permutations: [[u8; WIDTH]; PASSES],
    pub(crate) offset: usize,
    pub(crate) initial_state: [u8; WIDTH],
}

/// Derive the full schedule from the material, consuming the parameter source in the
/// order the format fixes.
pub(crate) fn derive_schedule(material: &Material) -> Schedule {
    let mut source = blake3::Hasher::new_keyed(material.network_params()).finalize_xof();

    let mut substitutions = [[0u8; 256]; PASSES];
    for table in substitutions.iter_mut() {
        let mut seed = [0u8; 256];
        source.fill(&mut seed);
        *table = derive_substitution_table(&seed);
    }

    // 0x736B7964_6576616C

    let mut permutations = [[0u8; WIDTH]; PASSES];
    for table in permutations.iter_mut() {
        let mut seed = [0u8; WIDTH];
        source.fill(&mut seed);
        *table = derive_position_permutation(&seed);
    }

    let mut offset_seed = [0u8; 1];
    source.fill(&mut offset_seed);
    let offset = ((offset_seed[0] as usize % 31) * 2) + 3;

    let mut initial_state = [0u8; WIDTH];
    source.fill(&mut initial_state);

    Schedule {
        substitutions,
        permutations,
        offset,
        initial_state,
    }
}

// NOTE (vendoring, rev 3 §3.1): laquna's `pub(crate) fn state_after`, gated
// behind `#[cfg(feature = "testing-internals")]`, is omitted — the
// testing-internals surface is not vendored (it exists only to snapshot
// round-by-round state for reference-vector generation; the generator itself
// always runs a full block).

/// Build a 256-entry substitution table by shuffling the identity table with `seed`.
///
/// `seed[0]` is read into the buffer but unused by the shuffle, which walks from the
/// top index down. Index selection is by modulo, which is mildly biased for small
/// indices; uniformity is not a requirement here.
fn derive_substitution_table(seed: &[u8; 256]) -> [u8; 256] {
    let mut table = [0u8; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        *slot = i as u8;
    }
    for i in (1..256).rev() {
        let j = seed[i] as usize % (i + 1);
        table.swap(i, j);
    }
    table
}

/// Build a 64-entry position permutation by shuffling the identity with `seed`.
///
/// As with the substitution table, `seed[0]` is unused by the shuffle.
fn derive_position_permutation(seed: &[u8; WIDTH]) -> [u8; WIDTH] {
    let mut table = [0u8; WIDTH];
    for (i, slot) in table.iter_mut().enumerate() {
        *slot = i as u8;
    }
    for i in (1..WIDTH).rev() {
        let j = seed[i] as usize % (i + 1);
        table.swap(i, j);
    }
    table
}

/// One pass over the working state: substitute, diffuse across positions, permute.
fn apply_pass(
    state: &mut [u8; WIDTH],
    substitution: &[u8; 256],
    permutation: &[u8; WIDTH],
    offset: usize,
) {
    // Substitute: a byte-local table lookup at each position.
    for slot in state.iter_mut() {
        *slot = substitution[*slot as usize];
    }

    // Diffuse: fold a partner `offset` positions away into each position. Computed into
    // a fresh buffer so every fold reads its partner's pre-diffusion value, never a
    // half-updated one. This cross-position fold is what stops the passes from
    // degenerating into a byte-local mapping.
    let mut diffused = [0u8; WIDTH];
    for i in 0..WIDTH {
        diffused[i] = state[i] ^ state[(i + offset) % WIDTH];
    }
    *state = diffused;

    // Permute: the byte at position `i` moves to position `permutation[i]`.
    let mut permuted = [0u8; WIDTH];
    for i in 0..WIDTH {
        permuted[permutation[i] as usize] = state[i];
    }
    *state = permuted;
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::materials::derive;

    const SEED: &[u8] =
        b"did:plc:7iza6de2dwap2sbkpav7c6c6||3laqlxv2k7s2y||laquna/v0.2";
    const SLUG: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    // All expected values below were produced by an independent from-scratch reference
    // implementation of this construction, so the checks are not self-referential.
    const EXPECT_FIRST_64: &str = "32b22e6559930133086d2b9ddd3636ca7e5624e110b26cbff2fb43511ba33eb8f0b2ef716585a97d7e30fc2c6ac0cd2bbfe8faeffd61dc0c88d7a2956eb26da3";
    const EXPECT_W0: &str = "63fb0322587a9ce5e2a78cb3fa608cc988eebb18410fae05ac0a6e1021bface8e6be710a14134d46b982e8a1216302ed8947e450a2e88ca0b0feb9b7000e5506";
    const EXPECT_W1: &str = "8378067c9b0ec9951a764d72de3017eba175f8743d5273476ab3d8be63667a5d8025bbd027a471aa1aaa67bb116831a4a517ac475c8ed5c66aebfb60b2e56d39";
    const EXPECT_W2: &str = "8af7dcaa2c797ceec10c139b448dc2781e801fb4c41451d8c0c303faf5c603df9ffa960e47342fa7b22631145f0b20370f3377a99e121ff17eb5db7dc419edaa";
    const EXPECT_OFFSET: usize = 59;

    fn expect(hex_str: &str) -> Vec<u8> {
        let mut out = alloc::vec![0u8; hex_str.len() / 2];
        hex::decode_to_slice(hex_str, &mut out).unwrap();
        out
    }

    fn generator() -> NetworkGenerator {
        NetworkGenerator::new(&derive(SEED, &SLUG))
    }

    #[test]
    fn first_block_matches_reference() {
        let bytes = generator().produce(64);
        assert_eq!(bytes, expect(EXPECT_FIRST_64));
    }

    /// Validate the pass arithmetic directly against the reference for the initial
    /// state and the states after one and two passes.
    #[test]
    fn pass_arithmetic_matches_reference() {
        let g = generator();
        assert_eq!(&g.state[..], expect(EXPECT_W0).as_slice());

        let mut w = g.state;
        apply_pass(&mut w, &g.substitutions[0], &g.permutations[0], g.offset);
        assert_eq!(&w[..], expect(EXPECT_W1).as_slice());

        apply_pass(&mut w, &g.substitutions[1], &g.permutations[1], g.offset);
        assert_eq!(&w[..], expect(EXPECT_W2).as_slice());
    }

    /// Regression guard against a pass-collapsing implementation: applying pass 2's
    /// distinct parameters must not equal re-applying pass 1's parameters to the
    /// one-pass state. A collapse (every pass identical) would fail this.
    #[test]
    fn passes_do_not_collapse() {
        let g = generator();

        let mut after_one = g.state;
        apply_pass(&mut after_one, &g.substitutions[0], &g.permutations[0], g.offset);

        let mut real_two = after_one;
        apply_pass(&mut real_two, &g.substitutions[1], &g.permutations[1], g.offset);

        let mut collapsed_two = after_one;
        apply_pass(&mut collapsed_two, &g.substitutions[0], &g.permutations[0], g.offset);

        assert_ne!(real_two, collapsed_two);
    }

    #[test]
    fn offset_is_odd_in_range() {
        let g = generator();
        assert_eq!(g.offset, EXPECT_OFFSET);
        assert_eq!(g.offset % 2, 1, "offset must be odd (so it is coprime with 64)");
        assert!((3..=63).contains(&g.offset), "offset must lie in [3, 63]");
    }

    /// A second material derives a different diffuse offset (55, not 59) and different
    /// output. This catches an implementation that hardcoded a single offset — the
    /// source-side equivalent of pinning two distinct-offset reference materials. Both
    /// the offset and the first block are checked against the independent reference.
    #[test]
    fn distinct_material_has_distinct_offset() {
        const SLUG2: [u8; 32] = [0xa5; 32];
        const EXPECT_OFFSET2: usize = 55;
        const EXPECT_FIRST_64_2: &str = "022695f9b7efeef263b244a2f5283051442226c755ac7f9341ee5ead81923794fa65db8414b7ebfb3867049db44ba4d19fa3b8b8872cc7445a45705aa3f8bf03";

        let g = NetworkGenerator::new(&derive(SEED, &SLUG2));
        assert_eq!(g.offset, EXPECT_OFFSET2);
        assert_ne!(g.offset, EXPECT_OFFSET, "the two materials must derive distinct offsets");

        let first = NetworkGenerator::new(&derive(SEED, &SLUG2)).produce(64);
        assert_eq!(first, expect(EXPECT_FIRST_64_2));
    }

    #[test]
    fn substitution_tables_are_permutations() {
        let g = generator();
        for table in &g.substitutions {
            let mut sorted = *table;
            sorted.sort_unstable();
            for (i, &v) in sorted.iter().enumerate() {
                assert_eq!(v as usize, i, "substitution table is not a permutation of 0..=255");
            }
        }
    }

    #[test]
    fn position_permutations_are_permutations() {
        let g = generator();
        for table in &g.permutations {
            let mut sorted = *table;
            sorted.sort_unstable();
            for (i, &v) in sorted.iter().enumerate() {
                assert_eq!(v as usize, i, "position permutation is not a permutation of 0..=63");
            }
        }
    }

    #[test]
    fn tables_are_distinct_across_passes() {
        let g = generator();
        for a in 0..PASSES {
            for b in (a + 1)..PASSES {
                assert_ne!(g.substitutions[a], g.substitutions[b], "substitutions {a},{b} equal");
                assert_ne!(g.permutations[a], g.permutations[b], "permutations {a},{b} equal");
            }
        }
    }

    #[test]
    fn deterministic_for_same_material() {
        assert_eq!(generator().produce(200), generator().produce(200));
    }

    #[test]
    fn differs_for_different_material() {
        let a = NetworkGenerator::new(&derive(SEED, &SLUG)).produce(200);
        let b = NetworkGenerator::new(&derive(b"a different seed", &SLUG)).produce(200);
        assert_ne!(a, b);
    }

    #[test]
    fn length_matches_request() {
        for len in [0usize, 1, 63, 64, 65, 200] {
            assert_eq!(generator().produce(len).len(), len);
        }
    }

    /// Producing across two calls continues the state, matching one larger call —
    /// exercises the block cursor across a non-aligned split.
    #[test]
    fn incremental_matches_single() {
        let single = generator().produce(150);
        let mut split = generator();
        let mut joined = split.produce(70);
        joined.extend_from_slice(&split.produce(80));
        assert_eq!(single, joined);
    }
}