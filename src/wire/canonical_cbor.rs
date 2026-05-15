// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RFC 8949 §4.2 deterministic CBOR encoding helper.
//!
//! `ciborium` produces RFC 8949 §4.2-compliant integer width and
//! definite-length array/map encoding by default, but it does NOT
//! enforce the §4.2.1 canonical map-key ordering: maps emit in the
//! order entries were added to the [`Value::Map`] vector.
//!
//! This module provides a [`canonicalize`] step that recursively
//! sorts every [`ciborium::Value::Map`] in a value tree by the
//! canonical-CBOR-encoded byte representation of each key
//! (length-then-bytewise). [`to_canonical_bytes`] composes
//! canonicalization with serialization so callers get a single
//! function: take a [`ciborium::Value`], get back the unique
//! canonical byte sequence per RFC 8949 §4.2.
//!
//! Phase 4b's §7 round-4 patch motivation: a non-canonical map
//! ordering produces two valid CBOR encodings of the same logical
//! payload, splitting signature inputs and creating an
//! alg-confusion-adjacent verifier-vs-issuer ambiguity.
//! Canonicalizing the encoding closes that ambiguity at the wire
//! layer.
//!
//! Receive-side defense: the verification path round-trips
//! received bytes through this module and rejects payloads whose
//! re-canonicalized form does not byte-equal the input. A
//! malicious sender cannot probe encoding ambiguities because
//! every accepted payload survives the round-trip check.

use ciborium::Value;

/// Encode a value tree as canonical RFC 8949 §4.2 CBOR.
///
/// Composes [`canonicalize`] with `ciborium::ser::into_writer` so
/// every nested [`Value::Map`] is sorted before encoding.
#[must_use]
pub(crate) fn to_canonical_bytes(value: Value) -> Vec<u8> {
    let canonical = canonicalize(value);
    let mut out = Vec::new();
    // ciborium's encoder is infallible for Value (no I/O errors
    // possible against a Vec<u8>; the type is finite and ciborium
    // does not surface encoding failures for in-memory values).
    ciborium::ser::into_writer(&canonical, &mut out)
        .expect("ciborium::ser::into_writer should not fail on Vec<u8>");
    out
}

/// Recursively canonicalize a [`Value`] tree per RFC 8949 §4.2.1.
///
/// Maps are sorted by the canonical-CBOR encoding of each key
/// (shorter encoding first; ties broken by bytewise lexicographic
/// comparison of the key's encoded bytes). Sub-values are
/// canonicalized depth-first.
///
/// Every other variant is returned as-is — ciborium's other
/// encodings already meet RFC 8949 §4.2 deterministic-encoding
/// rules (shortest-form integers, definite-length arrays).
#[must_use]
pub(crate) fn canonicalize(value: Value) -> Value {
    match value {
        Value::Map(entries) => {
            let mut canonical: Vec<(Vec<u8>, Value, Value)> = entries
                .into_iter()
                .map(|(k, v)| {
                    let encoded_key = encode_value(&k);
                    let canonical_v = canonicalize(v);
                    (encoded_key, canonicalize(k), canonical_v)
                })
                .collect();
            // RFC 8949 §4.2.1: shorter encoded key first; same
            // length sorted bytewise lexicographic.
            canonical.sort_by(|a, b| {
                a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0))
            });
            Value::Map(canonical.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize).collect())
        }
        Value::Tag(tag, inner) => Value::Tag(tag, Box::new(canonicalize(*inner))),
        // Atoms and binary blobs are already canonical.
        v @ (Value::Integer(_)
        | Value::Bytes(_)
        | Value::Float(_)
        | Value::Text(_)
        | Value::Bool(_)
        | Value::Null) => v,
        // ciborium::Value is `#[non_exhaustive]`-friendly; future
        // variants would land here. Treat them as opaque for now;
        // the canonicalization result still passes through encoding
        // correctly — only Map sorting is the round-1 patch
        // concern.
        other => other,
    }
}

/// Encode a single [`Value`] to bytes via ciborium for the
/// purpose of comparing keys during canonicalization. Equivalent
/// to `to_canonical_bytes` applied to the key but trimmed of
/// recursion since map keys in this crate are always atoms (text
/// strings) per the §4.8 wire format. Recursion is preserved
/// against future structural growth.
fn encode_value(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .expect("ciborium::ser::into_writer should not fail on Vec<u8>");
    out
}

/// Decode CBOR bytes into a [`Value`] tree.
///
/// `Err(())` on any decode failure; callers translate to the
/// appropriate error variant in their domain (e.g.,
/// [`crate::ClaimVerificationError::Malformed`]).
pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Value, ()> {
    ciborium::de::from_reader(bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Map entries inserted in non-canonical order produce the
    /// same byte sequence as entries in canonical order, after
    /// canonicalization. Without the canonicalize step, ciborium
    /// would emit insertion-order — that's the round-1 patch
    /// hazard we close here.
    #[test]
    fn map_entries_canonicalize_to_same_bytes_regardless_of_insertion_order() {
        let m1 = Value::Map(vec![
            (Value::Text("zebra".into()), Value::Integer(1.into())),
            (Value::Text("apple".into()), Value::Integer(2.into())),
            (Value::Text("mango".into()), Value::Integer(3.into())),
        ]);
        let m2 = Value::Map(vec![
            (Value::Text("apple".into()), Value::Integer(2.into())),
            (Value::Text("mango".into()), Value::Integer(3.into())),
            (Value::Text("zebra".into()), Value::Integer(1.into())),
        ]);
        let m3 = Value::Map(vec![
            (Value::Text("mango".into()), Value::Integer(3.into())),
            (Value::Text("zebra".into()), Value::Integer(1.into())),
            (Value::Text("apple".into()), Value::Integer(2.into())),
        ]);
        let b1 = to_canonical_bytes(m1);
        let b2 = to_canonical_bytes(m2);
        let b3 = to_canonical_bytes(m3);
        assert_eq!(b1, b2);
        assert_eq!(b1, b3);
    }

    /// RFC 8949 §4.2.1: shorter keys sort before longer keys. A
    /// 1-byte key `"a"` (CBOR-encoded as `0x61 0x61`) precedes a
    /// 3-byte key `"abc"` (encoded `0x63 0x61 0x62 0x63`).
    #[test]
    fn map_keys_sort_shorter_first_then_lexicographic() {
        let m = Value::Map(vec![
            (Value::Text("abc".into()), Value::Integer(1.into())),
            (Value::Text("a".into()), Value::Integer(2.into())),
            (Value::Text("ab".into()), Value::Integer(3.into())),
        ]);
        let canonical = canonicalize(m);
        let Value::Map(entries) = canonical else {
            panic!("expected Map");
        };
        let keys: Vec<&str> = entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(s) => s.as_str(),
                _ => unreachable!(),
            })
            .collect();
        // Shortest first, then bytewise lex among same-length.
        assert_eq!(keys, vec!["a", "ab", "abc"]);
    }

    /// Same-length keys sort bytewise lexicographic on the
    /// encoded form (which for ASCII text is the same as the
    /// string's lexicographic order).
    #[test]
    fn same_length_keys_sort_bytewise_lex() {
        let m = Value::Map(vec![
            (Value::Text("zoo".into()), Value::Integer(1.into())),
            (Value::Text("ant".into()), Value::Integer(2.into())),
            (Value::Text("dog".into()), Value::Integer(3.into())),
        ]);
        let canonical = canonicalize(m);
        let Value::Map(entries) = canonical else {
            panic!("expected Map");
        };
        let keys: Vec<&str> = entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(s) => s.as_str(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(keys, vec!["ant", "dog", "zoo"]);
    }

    /// Nested maps inside a parent map are themselves canonicalized.
    #[test]
    fn nested_maps_are_recursively_canonicalized() {
        let inner_unsorted = Value::Map(vec![
            (Value::Text("z".into()), Value::Integer(1.into())),
            (Value::Text("a".into()), Value::Integer(2.into())),
        ]);
        let outer = Value::Map(vec![(Value::Text("inner".into()), inner_unsorted)]);
        let canonical = canonicalize(outer);
        let Value::Map(outer_entries) = canonical else {
            panic!("expected outer Map");
        };
        let inner = &outer_entries[0].1;
        let Value::Map(inner_entries) = inner else {
            panic!("expected inner Map");
        };
        let keys: Vec<&str> = inner_entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(s) => s.as_str(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(keys, vec!["a", "z"]);
    }

    /// Maps inside arrays are canonicalized.
    #[test]
    fn maps_inside_arrays_are_canonicalized() {
        let m = Value::Map(vec![
            (Value::Text("z".into()), Value::Integer(1.into())),
            (Value::Text("a".into()), Value::Integer(2.into())),
        ]);
        let arr = Value::Array(vec![m]);
        let canonical = canonicalize(arr);
        let Value::Array(items) = canonical else {
            panic!("expected Array");
        };
        let Value::Map(entries) = &items[0] else {
            panic!("expected Map inside Array");
        };
        let first_key = match &entries[0].0 {
            Value::Text(s) => s.as_str(),
            _ => unreachable!(),
        };
        assert_eq!(first_key, "a");
    }

    /// Round-trip: canonical bytes decode back to the same Value
    /// tree (modulo map ordering, which canonicalize() then
    /// re-imposes).
    #[test]
    fn canonical_bytes_round_trip_through_decode() {
        let original = Value::Map(vec![
            (Value::Text("apple".into()), Value::Integer(1.into())),
            (Value::Text("zebra".into()), Value::Integer(2.into())),
        ]);
        let bytes = to_canonical_bytes(original.clone());
        let decoded = from_bytes(&bytes).unwrap();
        let recanonicalized = to_canonical_bytes(decoded);
        assert_eq!(bytes, recanonicalized);
    }

    /// Adversarial: a payload whose CBOR-level map is in
    /// non-canonical order (constructed by hand) decodes
    /// successfully via ciborium but its re-canonicalized bytes
    /// differ from the input. This is what the verify-side
    /// round-trip check catches.
    #[test]
    fn non_canonical_input_re_canonicalizes_to_different_bytes() {
        // CBOR-encoded `{"zebra": 1, "apple": 2}` (non-canonical:
        // "apple" should come before "zebra" by bytewise lex).
        // 0xA2 = map(2 entries)
        // 0x65 0x7A 0x65 0x62 0x72 0x61 = text(5) "zebra"
        // 0x01 = uint(1)
        // 0x65 0x61 0x70 0x70 0x6C 0x65 = text(5) "apple"
        // 0x02 = uint(2)
        let non_canonical: Vec<u8> = vec![
            0xA2, 0x65, 0x7A, 0x65, 0x62, 0x72, 0x61, 0x01, 0x65, 0x61, 0x70, 0x70,
            0x6C, 0x65, 0x02,
        ];
        let decoded = from_bytes(&non_canonical).unwrap();
        let re_canonicalized = to_canonical_bytes(decoded);
        assert_ne!(
            non_canonical, re_canonicalized,
            "non-canonical input should re-canonicalize to different bytes"
        );
    }
}
