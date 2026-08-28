# z-tenant-onboarding

A T3N TEE contract that runs **sanctions / PEP / adverse-media screening on a
counterparty without the operator ever holding that counterparty's personal
data.**

## Why this, specifically

Most "privacy-preserving" demos pick a workload that never needed the private
data in the first place. Screening is the opposite: it is the compliance check
that **structurally cannot run on anonymised input**, because the provider
matches on a real name and a real date of birth. There is no way to redact your
way out of it.

So in the normal architecture, every company that onboards a vendor or an
employee ends up with plaintext PII in three places it did not want it — the
app server that assembled the request, the log line that recorded it, and the
screening vendor's request history — all to obtain an output that is one word
long.

This contract removes all three. The request body it builds contains
`{{profile.first_name}}`, not a name. The host substitutes the real values
inside the enclave, *after* this code has finished running, during
`http-with-placeholders` dispatch. What crosses back out of WASM is a decision,
a hit count, and an audit row.

**The guarantee is structural, not procedural.** `world.wit` does not import
`host:interfaces/http`. Without a plain-HTTP capability there is no expressible
way for this contract to send a resolved value anywhere — no code review is
required to believe it, and CI fails the build if a later commit adds the
import.

## What it exports

| Function | Does | Outbound call |
|---|---|---|
| `run-check` | Screens the calling user, writes an audit row, returns the decision. | yes, placeholders only |
| `get-check` | Reads one recorded decision back. | no |
| `list-checks` | Range-scans the audit map for a compliance export. | no |

`run-check` input:

```json
{ "subject-ref": "vendor-8812", "check-type": "sanctions", "score-threshold": 0.85 }
```

`subject-ref` is **your** opaque id for the counterparty, not their identity.
It is rejected if it contains an `@` or whitespace, which refuses both raw
emails and human names — the audit map is not a place to accumulate PII through
the back door.

Output, which is also exactly what is stored:

```json
{
  "subject-ref": "vendor-8812",
  "decision": "clear",
  "check-type": "sanctions",
  "hit-count": 0,
  "checked-at": 1772000000,
  "seq-no": 41822,
  "provider-ref": "45210",
  "contract-version": "0.1.0"
}
```

`provider-ref` is the provider's own search id, so an auditor can pull the full
match detail from the provider directly, under their own access controls,
rather than this system having to store it.

## Design decisions worth knowing

**It never auto-rejects.** `decide()` returns `clear` only on zero hits;
anything else is `review`. A false positive against a sanctions list is a legal
problem for the operator, so a human makes that call — the contract's job is to
be certain about the easy case.

**A malformed provider response is an error, not a clear.** `total_hits`
missing from the payload returns an error rather than defaulting to zero.
Defaulting would silently clear every counterparty screened during a provider
outage, which is the worst bug this codebase could have.

**Error text can name a profile *field*, never its contents.** The provider
echoes `search_term` in its error envelope — post-substitution, that is the
subject's name — so a non-2xx response returns the status code and explicitly
withholds the body. `placeholder-unknown(field)` *is* surfaced, because "your
profile has no date_of_birth" is actionable and is not itself PII.

**The decision rules import no host interface.** Everything in `src/policy.rs`
runs on an ordinary toolchain, so the rules that decide whether someone is
cleared are covered by `cargo test` rather than only by a live testnet
round-trip. `src/screening.rs` holds what genuinely needs the enclave and is
kept thin on purpose.

**`list-checks` reports its own truncation.** The host's `scan` is one-shot
with no cursor across calls. A compliance export that silently stopped at 100
rows would be worse than one that failed, so a full result sets
`"truncated": true` and returns `next-start`.

## Layout

```
├── wit/
│   ├── world.wit                 the exported interface + the 4 host imports
│   └── deps/                     vendored host ABI (host-interfaces 2.1.0, host-tenant 1.0.0)
├── src/
│   ├── lib.rs                    wit-bindgen entry + Guest dispatch
│   ├── policy.rs                 pure decision logic — no host imports, unit-tested
│   └── screening.rs              host calls (wasm32 only)
├── client/
│   └── setup.ts                  one-shot tenant setup: maps, secret, register, ACLs
└── .github/workflows/ci.yml      host tests + wasm component build + capability assertion
```

## Build

There is no local build step to get wrong — CI does it on every push:

```bash
cargo test --lib                                # decision rules, host toolchain
cargo build --target wasm32-wasip2 --release    # the component itself
```

The component lands at `target/wasm32-wasip2/release/z_tenant_onboarding.wasm`.

CI additionally asserts, on the built artifact, that the WASM header says
*component* (not a bare core module — the usual symptom of a missing
`crate-type = ["cdylib"]`), and that `wasm-tools component wit` shows
`http-with-placeholders` present and plain `http` **absent**. That second check
is the security claim of this repo expressed as a test.

> Note: this repo deliberately does **not** ship a `.cargo/config.toml` pinning
> `build.target = "wasm32-wasip2"`, which the reference implementation does.
> With that file present, `cargo test` tries to build and run the test harness
> for wasm32 and cannot execute it, so the unit tests appear impossible to run
> locally. Passing `--target` on the build command instead keeps both paths
> working.

## Deploy

```bash
cp .env.example .env      # fill in T3N_API_KEY and ONBOARDING_API_KEY
npm install
npx tsx client/setup.ts
```

`setup.ts` creates `z:<tid>:secrets` and `z:<tid>:onboarding-audit`, seeds the
provider token, registers the contract, and then — the step most easily
forgotten — updates both map ACLs to include the returned `contractId`. Map
ACLs default to deny, and without that update the first `run-check` fails on an
opaque KV write error rather than anything that points at the cause.

## Maintenance notes for whoever picks this up

- **Changing the provider** is `PROVIDER_URL` / `PROVIDER_HOST` /
  `parse_provider_response` in `policy.rs`, plus the header in
  `screening.rs::run_check`. The rest of the contract is provider-agnostic.
  Update the egress allow-list on the grant to match, or every call returns
  `egress-denied`.
- **Adding a PII field** to the search means adding a `{{profile.<field>}}`
  marker. Keep markers flat and snake_case — the host rejects nested or
  non-snake-case markers with `placeholder-denied`. The
  `markers_are_flat_and_snake_case` test enforces this so the failure happens
  in CI rather than at dispatch.
- **Bumping the version** means bumping `CONTRACT_VERSION` *and* the Cargo
  version; a test asserts they match, because the audit row stamps the version
  and a mismatch misattributes past decisions.
- **Never add `host:interfaces/http`.** If a future feature seems to need it,
  it is almost certainly a call that should carry placeholders instead. CI
  fails on the import by design.

## Licence

MIT.
