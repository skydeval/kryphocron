//! Sealed-trait machinery (§4.3 unforgeability discipline).
//!
//! The [`Sealed`] trait is the supertrait every sealed public
//! trait in this crate carries. Because [`Sealed`] is not
//! `pub`-visible outside the crate, no consumer can write an
//! impl of any trait that has [`Sealed`] as a supertrait.
//!
//! The [`Token`] zero-sized struct is the private marker used
//! inside `PhantomData<sealed::Token>` fields on every type whose
//! construction must be gated to the crate's authority paths
//! (proofs, claims, verified evidence, predicate contexts,
//! resource ids). Because [`Token`] is `pub(crate)`-bounded and
//! has no public constructor, consumers in safe code cannot
//! synthesize values of these types via struct-literal syntax.

/// Crate-private marker carried in `PhantomData` fields of every
/// unforgeable-in-safe-code type.
///
/// `Token` is `pub(crate)` only. Code outside the crate cannot
/// name it, which makes any struct with a `PhantomData<Token>`
/// field unconstructible via struct-literal syntax in safe code
/// (the field has no public default and no public constructor).
pub(crate) struct Token;

/// Supertrait of every sealed public trait the crate exposes.
///
/// Adversarial implementations from outside the crate fail to
/// compile because [`Sealed`] is not nameable from outside the
/// crate's `sealed` module, which is not re-exported.
pub trait Sealed {}
