/**
 * One-shot tenant setup: register the compiled contract, create the two KV
 * maps scoped to the returned contract id, and seed the provider token.
 *
 *   npm i && npx tsx client/setup.ts
 *
 * ORDER MATTERS, and the docs never state it as a rule: a map's ACL names a
 * `contractId`, and that id does not exist until `contracts.register` returns
 * it, so registration must come FIRST. Worse, re-registering the same tail
 * allocates a NEW contract id while `maps.create` is idempotent
 * (`MapAlreadyExists`) — so on every redeploy the create is a silent no-op
 * that leaves the ACL naming the previous build's id. That is why this script
 * always calls `maps.update` after `maps.create`, on both maps, even on a
 * first run. Skipping it surfaces later as an opaque
 * `access denied: <caller> cannot <op> map` at run-check time, which points
 * at the map rather than at the redeploy that actually caused it.
 *
 * Requires in .env (see .env.example):
 *   T3N_API_KEY            developer key from the ADK claim page
 *   ONBOARDING_API_KEY     screening-provider token, seeded into z:<tid>:secrets
 */
import { readFileSync } from "node:fs";
import {
  T3nClient,
  TenantClient,
  setEnvironment,
  loadWasmComponent,
  fetchTrustedManifest,
  getNodeUrl,
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
  const wasmComponent = await loadWasmComponent();

  const key = required("T3N_API_KEY");
  const address = eth_get_address(key);

  const t3n = new T3nClient({
    trustAnchor: await fetchTrustedManifest("testnet"),
    wasmComponent,
    handlers: {
      EthSign: metamask_sign(address, undefined, key),
    },
  });

  await t3n.handshake(); // must precede authenticate()
  const did = await t3n.authenticate(createEthAuthInput(address));

  // Always read the DID back from the session — never construct or derive it.
  const tenantDid = did.value;
  const tenant = new TenantClient({ t3n, baseUrl: getNodeUrl(), tenantDid });
  await tenant.tenant.me(); // throws early if the tenant client is misconfigured
  console.log(`authenticated as ${tenantDid}`);
  console.log("  ^ put this in .env as TENANT_DID — run-check.ts needs it");

  // 1. Register first — every ACL below names the id this returns.
  const wasm = readFileSync(WASM_PATH);
  const { contractId } = await tenant.contracts.register({
    tail: CONTRACT_TAIL,
    version: CONTRACT_VERSION,
    wasm,
  });
  console.log(
    `registered ${CONTRACT_TAIL} v${CONTRACT_VERSION} -> ${contractId}`,
  );
  console.log("  ^ keep this id: there is no API to read a tail's current id back");

  // 2. Create the maps. ACLs default to DENY, so both lists are explicit.
  //    secrets: the contract reads the provider token. It never writes here —
  //    the tenant seeds it below over the control plane, which bypasses the
  //    writers ACL, so the map can stay contract-only.
  await tenant.maps.create({
    tail: SECRETS_MAP,
    visibility: "private",
    readers: { only: [contractId] },
    writers: { only: [contractId] },
  });

  //    audit: written by the contract, read back through the tenant's own
  //    control plane. Never public — the rows are PII-free by construction,
  //    but the fact that a given counterparty was screened at all is itself
  //    commercially sensitive.
  await tenant.maps.create({
    tail: AUDIT_MAP,
    visibility: "private",
    readers: { only: [contractId] },
    writers: { only: [contractId] },
  });

  // 3. Re-point both ACLs at THIS registration's id. On a first run this is a
  //    no-op; on every redeploy it is the step that keeps the contract able to
  //    reach its own maps. See the header comment.
  await tenant.maps.update({
    tail: SECRETS_MAP,
    readers: { only: [contractId] },
    writers: { only: [contractId] },
  });
  await tenant.maps.update({
    tail: AUDIT_MAP,
    readers: { only: [contractId] },
    writers: { only: [contractId] },
  });
  console.log("ACLs re-pointed at the current contract id");

  // 4. Seed the provider token. There is no set-credentials host function;
  //    `map-entry-set` is a control-plane write, so it lands even though the
  //    map's writers list names only the contract.
  await tenant.executeControl("map-entry-set", {
    map_name: tenant.canonicalName(SECRETS_MAP),
    key: "onboarding_api_key",
    value: required("ONBOARDING_API_KEY"),
  });
  console.log(`seeded onboarding_api_key into z:<tid>:${SECRETS_MAP}`);

  console.log(
    "\nsetup complete — run `npx tsx client/run-check.ts vendor-8812`",
  );
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
