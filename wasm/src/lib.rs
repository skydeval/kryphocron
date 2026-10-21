// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Browser encode for `tools.kryphocron.feed.postPrivate` records.
//!
//! One export, [`prepare_private_post`] (`preparePrivatePost` in JS). It takes
//! a post's content and record identity and returns the record fields to
//! write: the encoded content, its codec and generation, and the clear
//! fields. The caller writes the record at exactly that DID, collection and
//! rkey.
//!
//! Encode only, by design: this module exports no decode and no way to choose
//! the slug.

use base64::Engine as _;
use kryphocron::codec::laquna::encode_standalone;
use kryphocron::post_content::PostContent;
use serde_json::{Map, Value};
use wasm_bindgen::prelude::*;

/// Largest time accepted: JS numbers are exact integers up to 2^53 - 1.
const MAX_SECS: f64 = 9_007_199_254_740_991.0;

/// Prepare the encoded fields of a private post.
///
/// - `did`, `nsid`, `rkey`: where the record will be written.
/// - `content_json`: `{"text": string, "facets"?: array, "embed"?: object}`;
///   `text` is required (empty when the post has none).
/// - `now_secs`: the current time in Unix seconds (`Date.now() / 1000`).
///
/// Returns a JSON string of the fields to add to the record:
/// `encodedContent` (`{"$bytes": …}`), `encodedContentCodec`,
/// `encodedContentGeneration`, and whichever of `embedBlobs`, `mentionDids`,
/// `quote` and `mediaKinds` are non-empty. The record must not also carry
/// `text`, `facets` or `embed`.
///
/// # Errors
///
/// A JS `Error` when the identity or content is malformed, the time is out of
/// range, or the browser's CSRNG fails.
#[wasm_bindgen(js_name = preparePrivatePost)]
pub fn prepare_private_post(
    did: &str,
    nsid: &str,
    rkey: &str,
    content_json: &str,
    now_secs: f64,
) -> Result<String, JsError> {
    prepare(did, nsid, rkey, content_json, now_secs).map_err(|e| JsError::new(&e))
}

fn prepare(
    did: &str,
    nsid: &str,
    rkey: &str,
    content_json: &str,
    now_secs: f64,
) -> Result<String, String> {
    if !now_secs.is_finite() || !(0.0..=MAX_SECS).contains(&now_secs) {
        return Err("now_secs out of range".to_owned());
    }
    let content = parse_content(content_json)?;
    let encoded = encode_standalone(&content.to_payload(), did, nsid, rkey, now_secs as u64)
        .map_err(|e| e.to_string())?;

    let mut fields = Map::new();
    fields.insert(
        "encodedContent".to_owned(),
        serde_json::json!({
            "$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(&encoded.content)
        }),
    );
    fields.insert(
        "encodedContentCodec".to_owned(),
        Value::String(encoded.codec.as_str().to_owned()),
    );
    if let Some(generation) = &encoded.generation {
        fields.insert(
            "encodedContentGeneration".to_owned(),
            Value::String(generation.as_str().to_owned()),
        );
    }
    content.clear_fields().apply_to(&mut fields);
    Ok(Value::Object(fields).to_string())
}

fn parse_content(content_json: &str) -> Result<PostContent, String> {
    let Ok(Value::Object(mut content)) = serde_json::from_str::<Value>(content_json) else {
        return Err("content is not a JSON object".to_owned());
    };
    let text = match content.remove("text") {
        Some(Value::String(text)) => text,
        _ => return Err("content.text missing or not a string".to_owned()),
    };
    let facets = match content.remove("facets") {
        None | Some(Value::Null) => None,
        Some(facets @ Value::Array(_)) => Some(facets),
        Some(_) => return Err("content.facets not an array".to_owned()),
    };
    let embed = match content.remove("embed") {
        None | Some(Value::Null) => None,
        Some(embed @ Value::Object(_)) => Some(embed),
        Some(_) => return Err("content.embed not an object".to_owned()),
    };
    Ok(PostContent {
        text,
        facets,
        embed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:exampleexampleexample";
    const NSID: &str = "tools.kryphocron.feed.postPrivate";

    #[test]
    fn prepares_fields_and_clear_fields() {
        let content = r#"{"text":"hi @f","facets":[{"features":[{"$type":"app.bsky.richtext.facet#mention","did":"did:plc:f"}]}]}"#;
        let out: Value =
            serde_json::from_str(&prepare(DID, NSID, "3kabc", content, 1_700_000_000.0).unwrap())
                .unwrap();
        assert_eq!(out["encodedContentCodec"], "laquna/0.2");
        assert!(
            out["encodedContentGeneration"]
                .as_str()
                .unwrap()
                .starts_with("laquna/00000000001700000000/")
        );
        assert!(out["encodedContent"]["$bytes"].is_string());
        assert_eq!(out["mentionDids"], serde_json::json!(["did:plc:f"]));
        assert!(out.get("embedBlobs").is_none());
    }

    #[test]
    fn refuses_bad_input() {
        let ok = r#"{"text":"x"}"#;
        assert!(prepare("plc:x", NSID, "3k", ok, 0.0).is_err());
        assert!(prepare(DID, NSID, "3k", r#"{"facets":[]}"#, 0.0).is_err());
        assert!(prepare(DID, NSID, "3k", r#"{"text":"x","embed":[]}"#, 0.0).is_err());
        assert!(prepare(DID, NSID, "3k", ok, f64::NAN).is_err());
        assert!(prepare(DID, NSID, "3k", ok, -1.0).is_err());
        assert!(prepare(DID, NSID, "3k", ok, 1e300).is_err());
    }
}
