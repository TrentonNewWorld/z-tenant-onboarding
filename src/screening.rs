//! The thin layer that actually talks to the host.
//!
//! Everything here needs a live enclave, so it is compiled only for wasm32 and
//! kept as small as possible — every branch that can be decided without a host
//! call lives in `policy.rs`, where it is unit-tested.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::host::interfaces::http_with_placeholders as hwp;
use crate::host::interfaces::{kv_store, logging};
use crate::host::tenant::tenant_context;
use crate::policy::{self, AuditRecord, CheckType, ListArgs, RunCheckArgs, SubjectRefArgs};
use crate::CONTRACT_VERSION;

/// Render an `http-error` without ever interpolating a resolved value.
///
/// `placeholder-unknown` names a profile FIELD, not its contents, so it is safe
/// to surface and is by far the most useful error a caller can get: it means
/// the user's profile is missing something, not that they lack permission.
fn describe(e: hwp::HttpError) -> String {
    match e {
        hwp::HttpError::EgressDenied(host) => format!(
            "egress denied for {host} - add {} to the contract's http allow-list and re-grant",
            policy::PROVIDER_HOST
        ),
        hwp::HttpError::PlaceholderDenied(marker) => {
            format!("placeholder not permitted: {marker} (markers must be flat and snake_case)")
        }
        hwp::HttpError::PlaceholderUnknown(field) => {
            format!("the calling user's profile has no {field} - screening cannot run without it")
        }
        hwp::HttpError::PlaceholderNoUserContext => {
            "no user context bound: run-check must be invoked through the Session API by the \
             user being screened, not via /api/dev/exec"
                .to_string()
        }
        hwp::HttpError::UpstreamError(reason) => {
            format!("screening provider unreachable: {reason}")
        }
    }
}

fn tenant_map(tail: &str) -> String {
    policy::qualified_map_name(&tenant_context::tenant_did(), tail)
}

/// Read the provider token out of `z:<tid>:secrets`.
///
/// The token is fetched per call and never cached in a static: contract memory
/// is not a place to keep a credential any longer than one dispatch needs it.
fn api_token() -> Result<String, String> {
    let map = tenant_map(policy::SECRETS_MAP);
    let bytes = kv_store::get(&map, policy::SECRET_KEY)
        .map_err(|e| format!("kv read on {map}: {e}"))?
        .ok_or_else(|| {
            format!(
                "{} not found in {map} - seed it with the tenant SDK before invoking this contract",
                String::from_utf8_lossy(policy::SECRET_KEY)
            )
        })?;
    String::from_utf8(bytes)
        .map_err(|_| "provider token in secrets map is not valid UTF-8".to_string())
}

pub fn run_check(input: &[u8]) -> Result<Vec<u8>, String> {
    let args: RunCheckArgs =
        serde_json::from_slice(input).map_err(|e| format!("run-check: bad input JSON: {e}"))?;
    let subject_ref = policy::validate_subject_ref(&args.subject_ref)?;
    let check_type = CheckType::parse(args.check_type.as_deref())?;
    let threshold = policy::normalise_threshold(args.score_threshold);

    let body = policy::build_search_body(subject_ref, check_type, threshold);
    // Fail closed if the body somehow lost its placeholders.
    policy::assert_no_literal_pii(&body)?;

    let token = api_token()?;
    let payload = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

    // Only the opaque ref and the check type are logged. The request body is
    // NOT logged: post-substitution it would contain the subject's name.
    let _ = logging::info(&format!(
        "screening {subject_ref} ({}) via {}",
        check_type.as_str(),
        policy::PROVIDER_HOST
    ));

    let resp = hwp::call(&hwp::Request {
        method: hwp::Verb::Post,
        url: policy::PROVIDER_URL.to_string(),
        headers: Some(alloc::vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), format!("Token {token}")),
        ]),
        payload: Some(payload),
    })
    .map_err(describe)?;

    if resp.code != 200 && resp.code != 201 {
        // The provider echoes `search_term` in its error envelope, which is
        // post-substitution PII. Report the status only, never the body.
        let _ = logging::error(&format!("provider returned HTTP {}", resp.code));
        return Err(format!(
            "screening provider returned HTTP {} (response body withheld: it echoes the \
             substituted search term)",
            resp.code
        ));
    }

    let (hit_count, provider_ref) = policy::parse_provider_response(&resp.payload)?;

    let record = AuditRecord {
        subject_ref: subject_ref.to_string(),
        decision: policy::decide(hit_count).to_string(),
        check_type: check_type.as_str().to_string(),
        hit_count,
        checked_at: tenant_context::cluster_timestamp_secs(),
        seq_no: tenant_context::seq_no(),
        provider_ref,
        contract_version: CONTRACT_VERSION.to_string(),
    };

    let encoded = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    let audit = tenant_map(policy::AUDIT_MAP);
    kv_store::put(&audit, subject_ref.as_bytes(), &encoded)
        .map_err(|e| format!("kv write on {audit}: {e}"))?;

    let _ = logging::info(&format!(
        "{subject_ref}: {} ({} hit(s))",
        record.decision, record.hit_count
    ));
    Ok(encoded)
}

pub fn get_check(input: &[u8]) -> Result<Vec<u8>, String> {
    let args: SubjectRefArgs =
        serde_json::from_slice(input).map_err(|e| format!("get-check: bad input JSON: {e}"))?;
    let subject_ref = policy::validate_subject_ref(&args.subject_ref)?;
    let audit = tenant_map(policy::AUDIT_MAP);
    kv_store::get(&audit, subject_ref.as_bytes())
        .map_err(|e| format!("kv read on {audit}: {e}"))?
        .ok_or_else(|| format!("no screening on record for {subject_ref}"))
}

pub fn list_checks(input: &[u8]) -> Result<Vec<u8>, String> {
    // An empty body is a legitimate "list everything from the start".
    let args: ListArgs = if input.is_empty() {
        ListArgs::default()
    } else {
        serde_json::from_slice(input).map_err(|e| format!("list-checks: bad input JSON: {e}"))?
    };
    let limit = policy::normalise_limit(args.limit);
    let (start, end) = policy::scan_bounds(&args);
    let audit = tenant_map(policy::AUDIT_MAP);

    let rows = kv_store::scan(&audit, &start, &end, limit)
        .map_err(|e| format!("kv scan on {audit}: {e}"))?;

    // The scan is one-shot — there is no cursor across calls. If it came back
    // full, say so and hand the caller the key to resume from, rather than
    // letting a compliance export silently stop at 100 rows.
    let truncated = rows.len() as u32 == limit;
    let next_start = if truncated {
        rows.last()
            .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
    } else {
        None
    };

    let records: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|(_, v)| serde_json::from_slice(v).ok())
        .collect();

    serde_json::to_vec(&serde_json::json!({
        "records": records,
        "count": records.len(),
        "truncated": truncated,
        "next-start": next_start,
    }))
    .map_err(|e| e.to_string())
}
