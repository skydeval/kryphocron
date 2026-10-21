// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `tools.kryphocron.feed.postPrivate` content payload and its clear
//! fields, as the lexicon defines them.
//!
//! What a `laquna/0.2` `encodedContent` decodes to takes one of two forms:
//!
//! - **text form:** the post's text as UTF-8;
//! - **content form:** the byte [`CONTENT_FORM_MARKER`] (`0xFF`), then a UTF-8
//!   JSON object `{text, facets?, embed?}`. `0xFF` never starts valid UTF-8,
//!   so the two forms cannot be confused.
//!
//! In the content form the stored record carries no `text`, `facets` or
//! `embed`. Four clear fields are derived from the encoded content instead
//! ([`derive_clear_fields`]): `embedBlobs`, `mentionDids`, `quote` and
//! `mediaKinds`. They are set by the encoder, so a reader that decodes the
//! content can re-derive them and check what the encoder asserted.
//!
//! This sits above the content-codec seam: the codec still treats its input
//! as opaque bytes. These functions produce and read those bytes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{Map, Value};
use thiserror::Error;

/// The first byte of a content-form payload.
pub const CONTENT_FORM_MARKER: u8 = 0xFF;

/// A post's encoded content: what a content-form payload carries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PostContent {
    /// The post's text; empty when it has none.
    pub text: String,
    /// The post's facets (a JSON array), when it has any.
    pub facets: Option<Value>,
    /// The post's embed (a JSON object), when it has one.
    pub embed: Option<Value>,
}

/// Why a decoded payload is not a valid postPrivate payload.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PayloadError {
    /// A text-form payload that is not UTF-8.
    #[error("text-form payload is not UTF-8")]
    TextNotUtf8,
    /// A content-form payload that is not a JSON object.
    #[error("content-form payload is not a JSON object")]
    NotAnObject,
    /// `text` missing or not a string.
    #[error("content-form payload: text missing or not a string")]
    BadText,
    /// `facets` present but not an array.
    #[error("content-form payload: facets not an array")]
    BadFacets,
    /// `embed` present but not an object.
    #[error("content-form payload: embed not an object")]
    BadEmbed,
}

impl PostContent {
    /// The content-form payload: [`CONTENT_FORM_MARKER`] then the JSON object
    /// `{text, facets?, embed?}`. `facets` and `embed` appear only when
    /// present.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut content = Map::new();
        content.insert("text".to_string(), Value::String(self.text.clone()));
        if let Some(facets) = &self.facets {
            content.insert("facets".to_string(), facets.clone());
        }
        if let Some(embed) = &self.embed {
            content.insert("embed".to_string(), embed.clone());
        }
        let mut bytes = alloc::vec![CONTENT_FORM_MARKER];
        serde_json::to_writer(&mut bytes, &Value::Object(content))
            .expect("serialising a JSON value into a Vec does not fail");
        bytes
    }

    /// Read a decoded payload in either form. A text-form payload gives a
    /// [`PostContent`] with only `text`.
    ///
    /// # Errors
    ///
    /// [`PayloadError`] when the payload matches neither form.
    pub fn from_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        let Some(json) = payload.strip_prefix(&[CONTENT_FORM_MARKER]) else {
            let text = core::str::from_utf8(payload).map_err(|_| PayloadError::TextNotUtf8)?;
            return Ok(PostContent {
                text: text.to_string(),
                ..PostContent::default()
            });
        };
        let Ok(Value::Object(mut content)) = serde_json::from_slice::<Value>(json) else {
            return Err(PayloadError::NotAnObject);
        };
        let text = match content.remove("text") {
            Some(Value::String(text)) => text,
            _ => return Err(PayloadError::BadText),
        };
        let facets = match content.remove("facets") {
            None => None,
            Some(facets @ Value::Array(_)) => Some(facets),
            Some(_) => return Err(PayloadError::BadFacets),
        };
        let embed = match content.remove("embed") {
            None => None,
            Some(embed @ Value::Object(_)) => Some(embed),
            Some(_) => return Err(PayloadError::BadEmbed),
        };
        Ok(PostContent {
            text,
            facets,
            embed,
        })
    }

    /// The clear fields for this content ([`derive_clear_fields`]).
    #[must_use]
    pub fn clear_fields(&self) -> ClearFields {
        derive_clear_fields(self.facets.as_ref(), self.embed.as_ref())
    }
}

/// The clear fields a content-form record carries, derived from its encoded
/// facets and embed. An empty field is omitted from the record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClearFields {
    /// `embedBlobs`: every blob object (`$type: blob`) inside the embed,
    /// copied whole, in document order.
    pub embed_blobs: Vec<Value>,
    /// `mentionDids`: the DIDs of the mention facets, deduplicated, in
    /// first-appearance order.
    pub mention_dids: Vec<String>,
    /// `quote`: a strong ref `{uri, cid}` to the quoted record of a record or
    /// record-with-media embed.
    pub quote: Option<Value>,
    /// `mediaKinds`: the kinds of media the post's own embed carries, each at
    /// most once, `image` before `video`.
    pub media_kinds: Vec<&'static str>,
}

impl ClearFields {
    /// Write the non-empty fields into a record object under their lexicon
    /// names, and remove any that are empty (a stale or client-sent value is
    /// never kept).
    pub fn apply_to(&self, record: &mut Map<String, Value>) {
        let mut set = |name: &str, value: Option<Value>| match value {
            Some(v) => {
                record.insert(name.to_string(), v);
            }
            None => {
                record.remove(name);
            }
        };
        set(
            "embedBlobs",
            (!self.embed_blobs.is_empty()).then(|| Value::Array(self.embed_blobs.clone())),
        );
        set(
            "mentionDids",
            (!self.mention_dids.is_empty()).then(|| {
                Value::Array(
                    self.mention_dids
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                )
            }),
        );
        set("quote", self.quote.clone());
        set(
            "mediaKinds",
            (!self.media_kinds.is_empty()).then(|| {
                Value::Array(
                    self.media_kinds
                        .iter()
                        .map(|k| Value::String((*k).to_string()))
                        .collect(),
                )
            }),
        );
    }
}

/// Derive the clear fields from a post's facets and embed.
#[must_use]
pub fn derive_clear_fields(facets: Option<&Value>, embed: Option<&Value>) -> ClearFields {
    let mut fields = ClearFields::default();
    if let Some(facets) = facets {
        fields.mention_dids = mention_dids(facets);
    }
    if let Some(embed) = embed {
        fields.quote = quoted_record(embed);
        fields.media_kinds = media_kinds(embed);
        blob_objects(embed, &mut fields.embed_blobs);
    }
    fields
}

/// Image embeds, in the stock and the kryphocron vocabularies.
const IMAGE_EMBED_TYPES: [&str; 4] = [
    "app.bsky.embed.images",
    "app.bsky.embed.gallery",
    "tools.kryphocron.feed.postPublic#embedImage",
    "tools.kryphocron.feed.postPublic#embedGallery",
];

/// Video embeds, in the stock and the kryphocron vocabularies.
const VIDEO_EMBED_TYPES: [&str; 2] = [
    "app.bsky.embed.video",
    "tools.kryphocron.feed.postPublic#embedVideo",
];

/// Record embeds, in the stock and the kryphocron vocabularies.
const RECORD_TYPES: [&str; 2] = [
    "app.bsky.embed.record",
    "tools.kryphocron.feed.postPublic#embedRecord",
];

/// Record-with-media embeds, in the stock and the kryphocron vocabularies.
const RECORD_WITH_MEDIA_TYPES: [&str; 2] = [
    "app.bsky.embed.recordWithMedia",
    "tools.kryphocron.feed.postPublic#embedRecordWithMedia",
];

/// Mention facet features: the stock and the kryphocron vocabularies, and
/// the bare local form.
const MENTION_FEATURE_TYPES: [&str; 3] = [
    "app.bsky.richtext.facet#mention",
    "tools.kryphocron.feed.postPublic#mention",
    "#mention",
];

fn type_of(value: &Value) -> Option<&str> {
    value.get("$type")?.as_str()
}

/// The media kinds `embed` itself carries: from an image or video embed, or
/// the `media` of a record-with-media. Link cards, plain quotes and a quoted
/// post's own media are not the post's media.
fn media_kinds(embed: &Value) -> Vec<&'static str> {
    let media_type = match type_of(embed) {
        Some(t) if RECORD_WITH_MEDIA_TYPES.contains(&t) => embed.get("media").and_then(type_of),
        other => other,
    };
    match media_type {
        Some(t) if IMAGE_EMBED_TYPES.contains(&t) => alloc::vec!["image"],
        Some(t) if VIDEO_EMBED_TYPES.contains(&t) => alloc::vec!["video"],
        _ => Vec::new(),
    }
}

/// The DIDs `facets` mention, deduplicated, in first-appearance order.
fn mention_dids(facets: &Value) -> Vec<String> {
    let mut dids: Vec<String> = Vec::new();
    let features = facets
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|facet| facet.get("features")?.as_array())
        .flatten();
    for feature in features {
        let is_mention = type_of(feature).is_some_and(|t| MENTION_FEATURE_TYPES.contains(&t));
        if let (true, Some(did)) = (is_mention, feature.get("did").and_then(Value::as_str)) {
            if !dids.iter().any(|d| d == did) {
                dids.push(did.to_string());
            }
        }
    }
    dids
}

/// The strong ref (`{uri, cid}`) of the record `embed` quotes.
fn quoted_record(embed: &Value) -> Option<Value> {
    let t = type_of(embed)?;
    let strong_ref = if RECORD_TYPES.contains(&t) {
        embed.get("record")?
    } else if RECORD_WITH_MEDIA_TYPES.contains(&t) {
        embed.get("record")?.get("record")?
    } else {
        return None;
    };
    let mut quote = Map::new();
    quote.insert(
        "uri".to_string(),
        Value::String(strong_ref.get("uri")?.as_str()?.to_string()),
    );
    quote.insert(
        "cid".to_string(),
        Value::String(strong_ref.get("cid")?.as_str()?.to_string()),
    );
    Some(Value::Object(quote))
}

/// Every blob object (`$type: blob`) inside `value`, copied whole.
fn blob_objects(value: &Value, found: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if map.get("$type").and_then(Value::as_str) == Some("blob") {
                found.push(value.clone());
            } else {
                map.values().for_each(|v| blob_objects(v, found));
            }
        }
        Value::Array(items) => items.iter().for_each(|v| blob_objects(v, found)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn blob(cid: &str) -> Value {
        json!({"$type": "blob", "ref": {"$link": cid}, "mimeType": "image/jpeg", "size": 10})
    }

    #[test]
    fn content_form_round_trips() {
        let content = PostContent {
            text: "hello @a".into(),
            facets: Some(json!([{"index": {"byteStart": 6, "byteEnd": 8}, "features": []}])),
            embed: Some(json!({"$type": "app.bsky.embed.images", "images": []})),
        };
        let payload = content.to_payload();
        assert_eq!(payload[0], CONTENT_FORM_MARKER);
        assert_eq!(PostContent::from_payload(&payload).unwrap(), content);
    }

    #[test]
    fn content_form_omits_absent_facets_and_embed() {
        let payload = PostContent {
            text: String::new(),
            ..Default::default()
        }
        .to_payload();
        assert_eq!(&payload[1..], br#"{"text":""}"#);
    }

    #[test]
    fn text_form_reads_as_text_only() {
        let c = PostContent::from_payload("plain post".as_bytes()).unwrap();
        assert_eq!(
            c,
            PostContent {
                text: "plain post".into(),
                ..Default::default()
            }
        );
        assert_eq!(
            PostContent::from_payload(&[0xC3, 0x28]),
            Err(PayloadError::TextNotUtf8)
        );
    }

    #[test]
    fn malformed_content_form_is_refused() {
        let with = |json: &str| {
            let mut p = alloc::vec![CONTENT_FORM_MARKER];
            p.extend_from_slice(json.as_bytes());
            PostContent::from_payload(&p)
        };
        assert_eq!(with("[1]"), Err(PayloadError::NotAnObject));
        assert_eq!(with("not json"), Err(PayloadError::NotAnObject));
        assert_eq!(with(r#"{"facets":[]}"#), Err(PayloadError::BadText));
        assert_eq!(
            with(r#"{"text":"a","facets":{}}"#),
            Err(PayloadError::BadFacets)
        );
        assert_eq!(
            with(r#"{"text":"a","embed":[]}"#),
            Err(PayloadError::BadEmbed)
        );
    }

    #[test]
    fn mention_dids_dedup_in_order_across_vocabularies() {
        let facets = json!([
            {"features": [{"$type": "app.bsky.richtext.facet#mention", "did": "did:plc:b"}]},
            {"features": [
                {"$type": "app.bsky.richtext.facet#link", "uri": "https://x"},
                {"$type": "tools.kryphocron.feed.postPublic#mention", "did": "did:plc:a"},
                {"$type": "#mention", "did": "did:plc:b"}
            ]}
        ]);
        let f = derive_clear_fields(Some(&facets), None);
        assert_eq!(f.mention_dids, ["did:plc:b", "did:plc:a"]);
    }

    #[test]
    fn quote_and_media_from_record_with_media() {
        let embed = json!({
            "$type": "app.bsky.embed.recordWithMedia",
            "record": {"record": {"uri": "at://did:plc:q/app.bsky.feed.post/1", "cid": "bafyq"}},
            "media": {"$type": "app.bsky.embed.video", "video": blob("bafyv")}
        });
        let f = derive_clear_fields(None, Some(&embed));
        assert_eq!(
            f.quote,
            Some(json!({"uri": "at://did:plc:q/app.bsky.feed.post/1", "cid": "bafyq"}))
        );
        assert_eq!(f.media_kinds, ["video"]);
        assert_eq!(f.embed_blobs, [blob("bafyv")]);
    }

    #[test]
    fn plain_quote_has_no_media_and_images_count_as_image() {
        let quote = json!({"$type": "tools.kryphocron.feed.postPublic#embedRecord",
                           "record": {"uri": "at://x/y/z", "cid": "c"}});
        let f = derive_clear_fields(None, Some(&quote));
        assert!(f.media_kinds.is_empty());
        assert!(f.quote.is_some());

        let gallery = json!({"$type": "app.bsky.embed.gallery",
                             "items": [{"image": blob("b1")}, {"image": blob("b2")}]});
        let f = derive_clear_fields(None, Some(&gallery));
        assert_eq!(f.media_kinds, ["image"]);
        assert_eq!(f.embed_blobs, [blob("b1"), blob("b2")]);
        assert_eq!(f.quote, None);
    }

    #[test]
    fn link_card_is_not_media() {
        let card = json!({"$type": "app.bsky.embed.external",
                          "external": {"uri": "https://x", "thumb": blob("bt")}});
        let f = derive_clear_fields(None, Some(&card));
        assert!(f.media_kinds.is_empty());
        assert_eq!(
            f.embed_blobs,
            [blob("bt")],
            "a card's thumb is still a blob to keep"
        );
    }

    #[test]
    fn apply_to_sets_non_empty_and_removes_stale() {
        let mut record = Map::new();
        record.insert("mentionDids".into(), json!(["did:plc:stale"]));
        record.insert("mediaKinds".into(), json!(["video"]));
        let f = ClearFields {
            media_kinds: alloc::vec!["image"],
            ..Default::default()
        };
        f.apply_to(&mut record);
        assert_eq!(record.get("mediaKinds"), Some(&json!(["image"])));
        assert!(!record.contains_key("mentionDids"));
        assert!(!record.contains_key("embedBlobs"));
        assert!(!record.contains_key("quote"));
    }
}
