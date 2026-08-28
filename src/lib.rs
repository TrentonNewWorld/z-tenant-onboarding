//! z-tenant-onboarding — PII-safe counterparty screening on T3N.
//!
//! Sanctions and adverse-media screening is the one compliance check that
//! cannot be run on anonymised data: the provider matches on a real name and a
//! real date of birth. So in the normal architecture the operator ends up
//! holding plaintext PII — in their app server, in their logs, and in their
//! screening vendor's request history — purely to satisfy a check whose only
//! useful output is one word.
//!
//! Here the contract never holds it. `run-check` templates
//! `{{profile.<field>}}` markers into the provider request body and dispatches
//! through `http-with-placeholders`; the host resolves them from the calling
//! user's profile inside the enclave, after this code has finished running.
//! What comes back across the WIT boundary is a decision, a hit count and an
//! audit row — no name, no date of birth, by construction rather than by
//! discipline.
//!
//! The contract does not import `host:interfaces/http`. With no plain-HTTP
//! capability there is no expressible way for it to send a resolved value
//! anywhere; the guarantee is enforced by the capability set, not by review.
//!
//! # Exports
//!
//! | Function      | Does |
//! |---------------|------|
//! | `run-check`   | Screens the calling user, writes an audit row, returns the decision. |
//! | `get-check`   | Reads one recorded decision back. No outbound call. |
//! | `list-checks` | Range-scans the audit map for a compliance export. |
//!
//! # Before first use
//!
//! The tenant SDK must create two KV maps and seed the provider token — see
//! `client/setup.ts`:
//!
//! ```text
//! z:<tid>:secrets           writers: [tenant]     key: onboarding_api_key
//! z:<tid>:onboarding-audit  writers: [contractId] readers: [tenant]
//! ```
#![warn(clippy::style, missing_debug_implementations)]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

pub const CONTRACT_VERSION: &str = "0.1.0";

wit_bindgen::generate!({
    world: "tenant-onboarding",
    path: "wit",
    additional_derives: [
        serde::Deserialize,
        serde::Serialize,
    ],
    generate_all,
});

pub mod policy;

#[cfg(target_arch = "wasm32")]
mod screening;

#[derive(Debug)]
struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::tenant_onboarding::contracts::Guest for Component {
    fn run_check(
        req: exports::z::tenant_onboarding::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("run-check: missing input")?;
        screening::run_check(&input)
    }

    fn get_check(
        req: exports::z::tenant_onboarding::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("get-check: missing input")?;
        screening::get_check(&input)
    }

    fn list_checks(
        req: exports::z::tenant_onboarding::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        // list-checks takes no required arguments.
        let input = req.input.unwrap_or_default();
        screening::list_checks(&input)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;

    #[test]
    fn contract_version_is_semver() {
        let parts: alloc::vec::Vec<&str> = CONTRACT_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "CONTRACT_VERSION must be MAJOR.MINOR.PATCH");
        for part in parts {
            assert!(part.parse::<u32>().is_ok(), "each part must be numeric");
        }
    }

    /// The registered version must match what the audit record stamps, or a
    /// compliance export attributes decisions to the wrong contract build.
    #[test]
    fn cargo_version_matches_contract_version() {
        assert_eq!(CONTRACT_VERSION, env!("CARGO_PKG_VERSION"));
    }
}
