/**
 * One-shot tenant setup: create the two KV maps, seed the provider token,
 * register the compiled contract, and grant the audit map to it.
 *
 * Run this once per tenant, before the contract is ever invoked. It is
 * idempotent — re-running it updates the ACLs and re-registers the current
 * WASM under a new version rather than failing.
 *
 *   npm i && npx tsx client/setup.ts
 *
 * Requires in .env:
 *   T3N_API_KEY            developer key from the ADK claim page
 *   ONBOARDING_API_KEY     screening-provider token, seeded into z:<tid>:secrets
 */
import { readFileSync } from "node:fs";
import {
  T3nClient,
  TenantClient,
  setEnvironment,
  loadWasmComponent,
  eth_get_address,
  metamask_sign,
  createEthAuthInput,
} from "@terminal3/t3n-sdk";

const WASM_PATH =
  process.env.WASM_PATH ??
  "target/wasm32-wasip2/release/z_tenant_onboarding.wasm";
const CONTRACT_TAIL = "onboarding";
const SECRETS_MAP = "secrets";
const AUDIT_MAP = "onboarding-audit";
const CONTRACT_VERSION = "0.1.0";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set — see .env.example`);
  return v;
}

async function main() {
  setEnvironment("testnet");
  await loadWasmComponent();

  const key = required("T3N_API_KEY");
  const address = await eth_get_address(key);

  const client = new T3nClient();
  await client.handshake(); // must precede authenticate()
  const did = await client.authenticate(
    createEthAuthInput(address, (addr: string, msg: string) =>
      metamask_sign(addr, msg, key),
    ),
  );

  // Always read the DID back from the session — never construct or derive it.
  const tenantDid = did.value;
  const tenant = new TenantClient(client, tenantDid);
  console.log(`authenticated as ${tenantDid}`);

  // ACLs default to DENY. Both maps must name their writers explicitly.
  // secrets: the tenant writes the token; the contract only reads it.
  await tenant.maps.create({
    tail: SECRETS_MAP,
    visibility: "private",
    readers: [tenantDid],
    writers: [tenantDid],
  });

  // audit: written by the contract, read by the tenant. Never public — the
  // rows are PII-free by construction, but the fact that a given counterparty
  // was screened at all is itself commercially sensitive.
  await tenant.maps.create({
    tail: AUDIT_MAP,
    visibility: "private",
    readers: [tenantDid],
    writers: [tenantDid],
  });

  // Seed the provider token BEFORE registering — there is no set-credentials
  // host function; the contract reads this map at dispatch time.
  await tenant.maps.set({
    tail: SECRETS_MAP,
    key: "onboarding_api_key",
    value: required("ONBOARDING_API_KEY"),
  });
  console.log(`seeded onboarding_api_key into z:<tid>:${SECRETS_MAP}`);

  const wasm = readFileSync(WASM_PATH);
  const { contractId } = await tenant.contracts.register({
    tail: CONTRACT_TAIL,
    version: CONTRACT_VERSION,
    wasm,
  });
  console.log(`registered ${CONTRACT_TAIL} v${CONTRACT_VERSION} -> ${contractId}`);

  // The contract can only write its audit rows once it is itself a writer on
  // the map — this update is the step most easily forgotten, and its absence
  // shows up as an opaque kv write failure at run-check time.
  await tenant.maps.update({
    tail: AUDIT_MAP,
    readers: [tenantDid],
    writers: [tenantDid, contractId],
  });
  await tenant.maps.update({
    tail: SECRETS_MAP,
    readers: [tenantDid, contractId],
    writers: [tenantDid],
  });
  console.log("ACLs updated: contract may write audit rows and read secrets");
  console.log("\nsetup complete — run `npx tsx client/run-check.ts vendor-8812`");
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
