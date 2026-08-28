//! Pure decision logic — imports no host interface, on purpose.
//!
//! Everything in this module runs identically on the host toolchain and inside
//! the enclave, so the rules that actually decide whether a counterparty is
//! cleared are covered by ordinary `cargo test` rather than only by a live
//! testnet round-trip. `screening.rs` holds the parts that genuinely need the
//! host and stays deliberately thin.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Longest `subject_ref` we will accept. Keys land in a KV map, and an
/// unbounded key is a denial-of-service surface on the audit scan.
pub const MAX_SUBJECT_REF: usize = 64;
pub const MIN_SUBJECT_REF: usize = 3;

/// Default and ceiling for `list-checks`. The host rejects `limit == 0`
/// outright, so the default has to be non-zero.
pub const DEFAULT_LIST_LIMIT: u32 = 100;
pub const MAX_LIST_LIMIT: u32 = 1000;

/// The screening provider. Kept as one place to change rather than string
/// literals sprinkled through the call path.
pub const PROVIDER_HOST: &str = "api.complyadvantage.com";
pub const PROVIDER_URL: &str = "https://api.complyadvantage.com/searches";

/// Key under which the tenant SDK seeds the provider token into
/// `z:<tid>:secrets`. There is no `set-credentials` host function — the map is
/// populated from outside before the contract ever runs.
pub const SECRET_KEY: &[u8] = b"onboarding_api_key";
pub const SECRETS_MAP: &str = "secrets";
pub const AUDIT_MAP: &str = "onboarding-audit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckType {
    Sanctions,
    AdverseMedia,
    Pep,
}

impl CheckType {
    /// Provider-side filter name. Unknown values are a hard error rather than
    /// a silent fallback: quietly running a narrower check than the compliance
    /// officer asked for is the worst possible failure mode here.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None | Some("sanctions") => Ok(CheckType::Sanctions),
            Some("adverse-media") => Ok(CheckType::AdverseMedia),
            Some("pep") => Ok(CheckType::Pep),
            Some(other) => Err(format!(
                "unknown check-type {other:?} - expected \"sanctions\", \"adverse-media\" or \"pep\""
            )),
        }
    }

    pub fn provider_filter(self) -> &'static str {
        match self {
            CheckType::Sanctions => "sanction",
            CheckType::AdverseMedia => "adverse-media",
            CheckType::Pep => "pep",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CheckType::Sanctions => "sanctions",
            CheckType::AdverseMedia => "adverse-media",
            CheckType::Pep => "pep",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RunCheckArgs {
    #[serde(rename = "subject-ref", alias = "subject_ref")]
    pub subject_ref: String,
    #[serde(rename = "check-type", alias = "check_type", default)]
    pub check_type: Option<String>,
    #[serde(rename = "score-threshold", alias = "score_threshold", default)]
    pub score_threshold: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct SubjectRefArgs {
    #[serde(rename = "subject-ref", alias = "subject_ref")]
    pub subject_ref: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListArgs {
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub end: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// What gets written to the audit map and handed back to the caller.
/// Every field here is either an opaque id, a count, or a timestamp — the
/// shape is the guarantee that a decision can be exported to an auditor
/// without a PII review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    #[serde(rename = "subject-ref")]
    pub subject_ref: String,
    pub decision: String,
    #[serde(rename = "check-type")]
    pub check_type: String,
    #[serde(rename = "hit-count")]
    pub hit_count: u64,
    #[serde(rename = "checked-at")]
    pub checked_at: u64,
    #[serde(rename = "seq-no")]
    pub seq_no: u64,
    /// The provider's own search id, so an auditor can pull the full match
    /// detail from the provider directly under their own access controls.
    #[serde(rename = "provider-ref")]
    pub provider_ref: String,
    #[serde(rename = "contract-version")]
    pub contract_version: String,
}

/// `subject_ref` is the caller's opaque handle for a counterparty. It is used
/// as a KV key and echoed into the provider's `client_ref`, so it must not be
/// personal data: anything with an `@` or whitespace is refused, which rejects
/// both raw emails and human names without needing a heuristic that guesses.
pub fn validate_subject_ref(raw: &str) -> Result<&str, String> {
    let s = raw.trim();
    if s.len() < MIN_SUBJECT_REF || s.len() > MAX_SUBJECT_REF {
        return Err(format!(
            "subject-ref must be {MIN_SUBJECT_REF}-{MAX_SUBJECT_REF} characters, got {}",
            s.len()
        ));
    }
    if s.contains('@') || s.chars().any(char::is_whitespace) {
        return Err(
            "subject-ref looks like personal data - pass your own opaque id (e.g. \"vendor-8812\"), \
             not an email or a name"
                .to_string(),
        );
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err(
            "subject-ref may contain only ASCII letters, digits, '-', '_', '.' and ':'".to_string(),
        );
    }
    Ok(s)
}

/// A provider match score above which a hit is worth a human's time.
/// Clamped rather than rejected — a caller passing 1.4 means "be strict".
pub fn normalise_threshold(raw: Option<f64>) -> f64 {
    match raw {
        Some(v) if v.is_finite() => v.clamp(0.0, 1.0),
        _ => 0.85,
    }
}

/// `list-checks` limit, honouring the host's refusal of a zero limit.
pub fn normalise_limit(raw: Option<u32>) -> u32 {
    match raw {
        Some(0) | None => DEFAULT_LIST_LIMIT,
        Some(v) => v.min(MAX_LIST_LIMIT),
    }
}

/// Build the provider request body.
///
/// The three PII fields are `{{profile.<field>}}` markers, NOT values — this
/// function has no way to obtain the real ones and that is the point. The host
/// substitutes them during `http-with-placeholders` dispatch, inside the
/// enclave, after this contract has finished writing the body.
///
/// Markers are kept flat and snake_case: the host rejects a nested or
/// non-snake-case marker with `placeholder-denied`.
pub fn build_search_body(
    subject_ref: &str,
    check_type: CheckType,
    threshold: f64,
) -> serde_json::Value {
    serde_json::json!({
        "search_term": "{{profile.first_name}} {{profile.last_name}}",
        "client_ref": subject_ref,
        "score_threshold": threshold,
        "fuzziness": 0.6,
        "share_url": false,
        "filters": {
            "types": [check_type.provider_filter()],
            "birth_year": "{{profile.date_of_birth}}"
        }
    })
}

/// A hit count of zero is the only outcome that clears automatically. Anything
/// else is `review` — this contract never auto-rejects a counterparty, because
/// a false positive on a sanctions list is a legal problem for the operator
/// and a human has to look at it.
pub fn decide(hit_count: u64) -> &'static str {
    if hit_count == 0 {
        "clear"
    } else {
        "review"
    }
}

/// Pull `total_hits` and the provider's search id out of the provider payload.
///
/// A missing `total_hits` is an error, not a zero. Defaulting a screening
/// result to "no hits" when the response shape is unexpected would silently
/// clear a counterparty on a provider outage.
pub fn parse_provider_response(body: &[u8]) -> Result<(u64, String), String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("provider response was not JSON: {e}"))?;
    let data = v
        .get("content")
        .and_then(|c| c.get("data"))
        .ok_or("provider response missing content.data")?;
    let hit_count = data
        .get("total_hits")
        .and_then(serde_json::Value::as_u64)
        .ok_or("provider response missing content.data.total_hits - refusing to assume zero")?;
    let provider_ref = data
        .get("id")
        .map(|id| match id {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| "unknown".to_string());
    Ok((hit_count, provider_ref))
}

/// Guard against an operator ever putting a resolved value where a marker
/// belongs. Called on the body immediately before dispatch; if a caller has
/// somehow smuggled a literal into a field we template, we fail closed.
pub fn assert_no_literal_pii(body: &serde_json::Value) -> Result<(), String> {
    let term = body
        .get("search_term")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !term.contains("{{profile.") {
        return Err(
            "refusing to dispatch: search_term does not contain a profile placeholder, which \
             would mean subject PII was assembled inside WASM"
                .to_string(),
        );
    }
    Ok(())
}

/// `kv-store` takes the FULL `z:<tid>:<tail>` name. The tenant DID arrives as
/// raw bytes from `tenant-context` and has to be hex-encoded first — passing
/// the raw bytes is the single most common way this call fails.
pub fn qualified_map_name(tenant_did: &[u8], tail: &str) -> String {
    format!("z:{}:{}", hex::encode(tenant_did), tail)
}

/// Half-open `[start, end)` bounds for the audit scan. An absent `end` becomes
/// `0xFF`-terminated so the scan covers the whole map.
pub fn scan_bounds(args: &ListArgs) -> (Vec<u8>, Vec<u8>) {
    let start = args.start.as_deref().unwrap_or("").as_bytes().to_vec();
    let end = match args.end.as_deref() {
        Some(e) => e.as_bytes().to_vec(),
        None => alloc::vec![0xFFu8; 8],
    };
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_email_as_subject_ref() {
        let err = validate_subject_ref("jane.doe@example.com").unwrap_err();
        assert!(err.contains("personal data"), "got: {err}");
    }

    #[test]
    fn rejects_a_human_name_as_subject_ref() {
        assert!(validate_subject_ref("Jane Doe").is_err());
    }

    #[test]
    fn rejects_too_short_and_too_long_refs() {
        assert!(validate_subject_ref("ab").is_err());
        let long = "v".repeat(MAX_SUBJECT_REF + 1);
        assert!(validate_subject_ref(&long).is_err());
    }

    #[test]
    fn accepts_an_opaque_ref_and_trims_it() {
        assert_eq!(validate_subject_ref("  vendor-8812 ").unwrap(), "vendor-8812");
    }

    #[test]
    fn rejects_control_and_unicode_refs() {
        assert!(validate_subject_ref("vendor\u{202e}8812").is_err());
    }

    #[test]
    fn unknown_check_type_is_an_error_not_a_fallback() {
        assert!(CheckType::parse(Some("everything")).is_err());
        assert_eq!(CheckType::parse(None).unwrap(), CheckType::Sanctions);
        assert_eq!(CheckType::parse(Some("pep")).unwrap(), CheckType::Pep);
    }

    #[test]
    fn threshold_is_clamped_not_rejected() {
        assert_eq!(normalise_threshold(Some(1.4)), 1.0);
        assert_eq!(normalise_threshold(Some(-2.0)), 0.0);
        assert_eq!(normalise_threshold(None), 0.85);
        assert_eq!(normalise_threshold(Some(f64::NAN)), 0.85);
    }

    #[test]
    fn limit_never_reaches_the_host_as_zero() {
        assert_eq!(normalise_limit(Some(0)), DEFAULT_LIST_LIMIT);
        assert_eq!(normalise_limit(None), DEFAULT_LIST_LIMIT);
        assert_eq!(normalise_limit(Some(9_999)), MAX_LIST_LIMIT);
        assert_eq!(normalise_limit(Some(7)), 7);
    }

    #[test]
    fn search_body_carries_markers_never_values() {
        let body = build_search_body("vendor-8812", CheckType::Sanctions, 0.9);
        let s = serde_json::to_string(&body).unwrap();
        assert!(s.contains("{{profile.first_name}}"));
        assert!(s.contains("{{profile.last_name}}"));
        assert!(s.contains("{{profile.date_of_birth}}"));
        // the opaque ref is the ONLY caller-supplied string in the body
        assert!(s.contains("vendor-8812"));
        assert!(assert_no_literal_pii(&body).is_ok());
    }

    #[test]
    fn markers_are_flat_and_snake_case() {
        // the host rejects nested / non-snake-case markers with placeholder-denied
        let body = build_search_body("vendor-1", CheckType::Pep, 0.85);
        let s = serde_json::to_string(&body).unwrap();
        for marker in s.split("{{profile.").skip(1) {
            let field = marker.split("}}").next().unwrap();
            assert!(!field.contains('.'), "nested marker: {field}");
            assert!(
                field.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "non-snake-case marker: {field}"
            );
        }
    }

    #[test]
    fn fails_closed_if_the_placeholder_is_gone() {
        let body = serde_json::json!({ "search_term": "Jane Doe" });
        assert!(assert_no_literal_pii(&body).is_err());
    }

    #[test]
    fn zero_hits_clears_anything_else_reviews() {
        assert_eq!(decide(0), "clear");
        assert_eq!(decide(1), "review");
        assert_eq!(decide(9_000), "review");
    }

    #[test]
    fn parses_a_real_shaped_provider_response() {
        let body = br#"{"content":{"data":{"id":45210,"ref":"AB-1","total_hits":0}}}"#;
        let (hits, r) = parse_provider_response(body).unwrap();
        assert_eq!(hits, 0);
        assert_eq!(r, "45210");
    }

    #[test]
    fn missing_total_hits_is_an_error_not_a_clear() {
        let body = br#"{"content":{"data":{"id":1}}}"#;
        let err = parse_provider_response(body).unwrap_err();
        assert!(err.contains("refusing to assume zero"), "got: {err}");
    }

    #[test]
    fn garbage_provider_body_is_an_error() {
        assert!(parse_provider_response(b"<html>502</html>").is_err());
        assert!(parse_provider_response(b"{}").is_err());
    }

    #[test]
    fn map_name_hex_encodes_the_raw_did_bytes() {
        let did = [0xDEu8, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            qualified_map_name(&did, "secrets"),
            "z:deadbeef:secrets".to_string()
        );
    }

    #[test]
    fn scan_bounds_default_to_the_whole_map() {
        let (s, e) = scan_bounds(&ListArgs::default());
        assert!(s.is_empty());
        assert!(e.iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn audit_record_round_trips_and_holds_no_pii_fields() {
        let rec = AuditRecord {
            subject_ref: "vendor-8812".into(),
            decision: "clear".into(),
            check_type: "sanctions".into(),
            hit_count: 0,
            checked_at: 1_772_000_000,
            seq_no: 42,
            provider_ref: "45210".into(),
            contract_version: "0.1.0".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
        for banned in ["first_name", "last_name", "date_of_birth", "email"] {
            assert!(!json.contains(banned), "audit record leaked {banned}");
        }
    }

    #[test]
    fn args_accept_both_kebab_and_snake_case() {
        let a: RunCheckArgs = serde_json::from_str(r#"{"subject-ref":"vendor-1"}"#).unwrap();
        assert_eq!(a.subject_ref, "vendor-1");
        let b: RunCheckArgs =
            serde_json::from_str(r#"{"subject_ref":"vendor-2","check_type":"pep"}"#).unwrap();
        assert_eq!(b.subject_ref, "vendor-2");
        assert_eq!(
            CheckType::parse(b.check_type.as_deref()).unwrap(),
            CheckType::Pep
        );
    }
}
