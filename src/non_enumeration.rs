//! §4.6 Non-enumeration response shape.

/// Non-enumeration response wrapper.
///
/// Collapses "doesn't exist" and "exists but unauthorized" into a
/// single externally-indistinguishable variant
/// ([`Outcome::NotFoundOrHidden`]). Distinguishing them requires
/// explicit audit-logged elevation; the default response shape
/// foreclosed enumeration through the public wire.
///
/// See §4.6.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T> {
    /// The target exists and the viewer is authorized.
    Found(T),
    /// Either the target does not exist OR it exists and the
    /// viewer is not authorized. The wire response does not
    /// distinguish the two cases.
    NotFoundOrHidden,
}

impl<T> Outcome<T> {
    /// True iff this is [`Outcome::Found`].
    #[must_use]
    pub fn is_found(&self) -> bool {
        matches!(self, Outcome::Found(_))
    }

    /// Unwrap to [`Option<T>`].
    pub fn into_option(self) -> Option<T> {
        match self {
            Outcome::Found(t) => Some(t),
            Outcome::NotFoundOrHidden => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_v1_variant_set_pinned() {
        // §4.6 commits exactly two variants. From inside the
        // defining crate the compiler treats #[non_exhaustive]
        // enums as exhaustive; adding a new variant breaks this
        // match.
        let o: Outcome<i32> = Outcome::Found(42);
        match o {
            Outcome::Found(_) | Outcome::NotFoundOrHidden => {}
        }
    }
}
