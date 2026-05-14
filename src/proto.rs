//! Placeholder proto-blue / ATProto types.
//!
//! Phase 1 ships **minimal opaque newtypes** for the ATProto and
//! proto-blue types that §4 surfaces refer to ([`Did`], [`Nsid`],
//! [`Rkey`], [`Cid`], [`AtUri`]). Phase 2 (§5 lexicon strategy)
//! swaps these for the real `proto-blue-lexicon` types per §9.5;
//! see CHAINLINKS #3.
//!
//! These placeholders implement the minimum trait surface that §4
//! relies on: equality, hashing, debug, and string-based
//! construction. The fields are private; constructors validate
//! shape so the canonicalization properties §4.4 commits
//! ([`crate::target::TargetRepresentation`]) hold against the
//! placeholders too.

use core::fmt;

use thiserror::Error;

/// ATProto Decentralized Identifier.
///
/// Wraps a UTF-8 string. Phase 1 stores the DID as supplied; full
/// did:plc / did:web validation lives behind the [`crate::resolver`]
/// surface in Phase 4.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Did(String);

impl Did {
    /// Construct a [`Did`] from a string. Phase 1 accepts any
    /// non-empty UTF-8 input; Phase 2 hardens parsing against the
    /// `proto-blue-lexicon` `Did` validator.
    pub fn new(raw: impl Into<String>) -> Result<Self, ProtoParseError> {
        let s = raw.into();
        if s.is_empty() {
            return Err(ProtoParseError::Empty);
        }
        Ok(Did(s))
    }

    /// Borrow the raw string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Did({})", self.0)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// ATProto namespaced identifier (NSID), e.g.
/// `tools.kryphocron.feed.postPrivate`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Nsid(String);

impl Nsid {
    /// Construct an [`Nsid`] from a string. Phase 1 accepts any
    /// non-empty UTF-8 input; Phase 2 enforces the dotted-segment
    /// grammar against `proto-blue-lexicon`.
    pub fn new(raw: impl Into<String>) -> Result<Self, ProtoParseError> {
        let s = raw.into();
        if s.is_empty() {
            return Err(ProtoParseError::Empty);
        }
        Ok(Nsid(s))
    }

    /// Borrow the raw string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Nsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nsid({})", self.0)
    }
}

impl fmt::Display for Nsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// ATProto record key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Rkey(String);

impl Rkey {
    /// Construct an [`Rkey`].
    pub fn new(raw: impl Into<String>) -> Result<Self, ProtoParseError> {
        let s = raw.into();
        if s.is_empty() {
            return Err(ProtoParseError::Empty);
        }
        Ok(Rkey(s))
    }

    /// Borrow the raw string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Rkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rkey({})", self.0)
    }
}

/// Content-addressable identifier (CID).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Cid(String);

impl Cid {
    /// Construct a [`Cid`].
    pub fn new(raw: impl Into<String>) -> Result<Self, ProtoParseError> {
        let s = raw.into();
        if s.is_empty() {
            return Err(ProtoParseError::Empty);
        }
        Ok(Cid(s))
    }

    /// Borrow the raw string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({})", self.0)
    }
}

/// AT URI (`at://did:.../collection/rkey`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AtUri(String);

impl AtUri {
    /// Construct an [`AtUri`].
    pub fn new(raw: impl Into<String>) -> Result<Self, ProtoParseError> {
        let s = raw.into();
        if !s.starts_with("at://") {
            return Err(ProtoParseError::MalformedUri);
        }
        Ok(AtUri(s))
    }

    /// Borrow the raw string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AtUri({})", self.0)
    }
}

/// Parse error returned by the placeholder proto-blue constructors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtoParseError {
    /// Input string was empty.
    #[error("input was empty")]
    Empty,
    /// AT URI did not begin with `at://`.
    #[error("malformed AT URI")]
    MalformedUri,
}

/// An NSID not present in the closed-namespace registry.
///
/// Returned by [`crate::tier::Tier::from_nsid`] when called with an
/// NSID that is not in the kryphocron-managed registry. The lexicon
/// registry itself ships in the companion `kryphocron-lexicons`
/// crate (Phase 2; §5.3).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UnknownNsid {
    /// The NSID was not present in the closed-namespace registry.
    #[error("NSID `{0}` is not present in the closed-namespace registry")]
    NotRegistered(Nsid),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_rejects_empty() {
        assert!(matches!(Did::new(""), Err(ProtoParseError::Empty)));
    }

    #[test]
    fn aturi_requires_scheme() {
        assert!(matches!(
            AtUri::new("did:plc:example/collection/rkey"),
            Err(ProtoParseError::MalformedUri)
        ));
        assert!(AtUri::new("at://did:plc:example/collection/rkey").is_ok());
    }

    #[test]
    fn proto_types_are_clone_eq_hash() {
        // Compile-time check: the trait bounds we rely on hold.
        fn assert_traits<T: Clone + Eq + std::hash::Hash + std::fmt::Debug>() {}
        assert_traits::<Did>();
        assert_traits::<Nsid>();
        assert_traits::<Rkey>();
        assert_traits::<Cid>();
        assert_traits::<AtUri>();
    }
}
