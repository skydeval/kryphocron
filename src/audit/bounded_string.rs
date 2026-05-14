//! Length-bounded string newtype for §6.5 audit-event payloads.
//!
//! [`BoundedString<N>`] wraps a [`String`] whose UTF-8 byte length
//! has been validated at construction to fit within `N` bytes.
//! The validating constructor returns [`BoundedStringTooLong`]
//! for over-length input; downstream audit-event construction
//! paths surface the failure to the operator (e.g.,
//! [`crate::wire::ClaimConstructionError`]) rather than at
//! audit-emit time, so the audit-emit path is infallible-on-length.
//!
//! [`crate::audit::ModeratorRationale::Declared`] is the v1
//! consumer; round-1 patch F2 added the bound at
//! [`crate::audit::MAX_RATIONALE_LEN`] = 4096 bytes.

use thiserror::Error;

/// Failure constructing a [`BoundedString<N>`] (§6.5 round-1
/// patch F2).
///
/// `len` reports the offending byte length so callers can surface
/// a precise diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("string too long: {len} bytes exceeds bound {bound}")]
pub struct BoundedStringTooLong {
    /// Observed byte length of the over-long input.
    pub len: usize,
    /// Configured bound (the `N` of [`BoundedString<N>`]).
    pub bound: usize,
}

/// UTF-8 string with a compile-time byte-length bound.
///
/// `N` is the inclusive maximum byte length of the wrapped
/// [`String`]. v1 audit events use [`BoundedString<4096>`] for
/// [`crate::audit::ModeratorRationale`] (§6.5 / round-1 patch F2).
///
/// Construction is fallible; access is infallible. The wrapped
/// string is owned and immutable post-construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedString<const N: usize> {
    inner: String,
}

impl<const N: usize> BoundedString<N> {
    /// Construct a [`BoundedString<N>`] from any string-convertible
    /// input. Validates the byte length against `N`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedStringTooLong`] when `s.len()` (byte count,
    /// not character count) exceeds `N`.
    pub fn new(s: impl Into<String>) -> Result<Self, BoundedStringTooLong> {
        let inner = s.into();
        if inner.len() > N {
            return Err(BoundedStringTooLong {
                len: inner.len(),
                bound: N,
            });
        }
        Ok(BoundedString { inner })
    }

    /// Borrow the wrapped string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Consume the wrapper and return the wrapped string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.inner
    }

    /// Byte length of the wrapped string.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the wrapped string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §6.5 round-1 patch F2: strings up to and including the
    /// bound succeed; strings longer than the bound fail.
    #[test]
    fn bounded_string_accepts_at_bound_rejects_past_bound() {
        const N: usize = 16;
        // Empty: ok.
        assert!(BoundedString::<N>::new("").is_ok());
        // Exactly N bytes: ok.
        let exact = "a".repeat(N);
        let ok = BoundedString::<N>::new(exact.clone()).unwrap();
        assert_eq!(ok.len(), N);
        assert_eq!(ok.as_str(), exact);
        // N+1 bytes: rejected.
        let over = "a".repeat(N + 1);
        let err = BoundedString::<N>::new(over).unwrap_err();
        assert_eq!(err.len, N + 1);
        assert_eq!(err.bound, N);
    }

    /// §6.5: validation is on bytes, not characters. A multi-byte
    /// UTF-8 char that pushes past the bound is rejected even when
    /// the character count is small.
    #[test]
    fn bounded_string_validates_bytes_not_chars() {
        const N: usize = 3;
        // "é" is two bytes in UTF-8; "éé" is four.
        assert!(BoundedString::<N>::new("é").is_ok());
        assert!(BoundedString::<N>::new("éé").is_err());
    }
}
