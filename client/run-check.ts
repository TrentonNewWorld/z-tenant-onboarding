/**
 * Screen one counterparty end to end, then read the audit row back.
 *
 *   npx tsx client/run-check.ts vendor-8812 [sanctions|adverse-media|pep]
 *
 * Run `client/setup.ts` once first — this script assumes the contract is
 * registered and both maps exist with current ACLs.
 *
 * Three separate identities are in play, and conflating them is the single
 * most common way this fails:
 *   - the TENANT (T3N_API_KEY) owns the contract and the maps. Not used here.
 *   - the AGENT (AGENT_KEY) invokes the contract. Its DID has its OWN credit
 *     balance, starting at zero — a metered call with an unfunded agent key
 *     fails with InsufficientCreditError.
 *   - the USER (USER_KEY) is the data owner whose profile the host resolves
 *     `{{profile.*}}` markers from. The user must sign an `agent-auth-update`
 *     grant naming the agent, the contract, the functions AND the hosts, or
 *     the outbound screening call is denied with `host/http.egress_denied`.
 *
 * Requires in .env (see .env.example):
 *   AGENT_KEY, USER_KEY, TENANT_DID, SCREENING_HOST
 */
import {
  T3nClient,
  setEnvironment,
  loadWasmComponent,
  fetchTrustedManifest,
  createEthAuthInput,
  eth_get_address,
  metamask_sign,
  getContractVersion,
  getNodeUrl,
} from "@terminal3/t3n-sdk";

const CONTRACT_TAIL = "onboarding";
const USER_CONTRACTS = "tee:user/contracts";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set — see .env.example`);
  return v;
}

/** Build and authenticate one session from a raw key. */
async function session(key: string, wasmComponent: unknown) {
  const address = eth_get_address(key);
  const client = new T3nClient({
    trustAnchor: await fetchTrustedManifest("testnet"),
    wasmComponent,
    handlers: { EthSign: metamask_sign(address, undefined, key) },
  });
  await client.handshake();
  const auth = await client.authenticate(createEthAuthInput(address));
  return { client, did: auth.value };
}

async function main() {
  const subjectRef = process.argv[2];
  const checkType = process.argv[3] ?? "sanctions";
  if (!subjectRef) {
    throw new Error(
      "usage: npx tsx client/run-check.ts <subject-ref> [check-type]\n" +
        "  subject-ref is YOUR opaque id for the counterparty (e.g. vendor-8812).\n" +
        "  It must not be a name, an email, or anything else personal — the\n" +
        "  contract rejects those, which is the point of the design.",
    );
  }

  setEnvironment("testnet");
  const wasmComponent = await loadWasmComponent();

  // The tenant DID is recorded by setup.ts. It is read back from a session
  // there and merely carried here — never derived from an address.
  const tenantDid = required("TENANT_DID");
  const contractId = `z:${tenantDid.replace(/^did:t3n:/, "")}:${CONTRACT_TAIL}`;

  const agent = await session(required("AGENT_KEY"), wasmComponent);
  const user = await session(required("USER_KEY"), wasmComponent);
  console.log(`agent ${agent.did}\nuser  ${user.did}`);

  const nodeUrl = getNodeUrl();
  const contractVersion = await getContractVersion(nodeUrl, contractId);

  // The USER grants the agent access — scoped to this contract, these three
  // functions, and exactly one host. `allowedHosts` is resolved per-call from
  // this grant, not from the contract's WIT imports: the imports say the
  // contract MAY dial out, the grant says where.
  const userContractVersion = await getContractVersion(nodeUrl, USER_CONTRACTS);
  await user.client.execute({
    contract_id: USER_CONTRACTS,
    contract_version: userContractVersion,
    function_name: "agent-auth-update",
    input: {
      agents: [
        {
          agentDid: agent.did,
          scripts: [
            {
              scriptName: contractId,
              versionReq: contractVersion,
              functions: ["run-check", "get-check", "list-checks"],
              allowedHosts: [required("SCREENING_HOST")],
            },
          ],
        },
      ],
    },
  });
  console.log(`grant signed: ${agent.did} may call ${contractId}`);

  // Screen. No PII crosses this boundary in either direction: the request
  // carries an opaque subject-ref, and the provider match on name and DOB is
  // resolved host-side from the user's profile after this code has run.
  const decision = await agent.client.executeAndDecode({
    contract_id: contractId,
    contract_version: contractVersion,
    function_name: "run-check",
    input: { "subject-ref": subjectRef, "check-type": checkType },
  });
  console.log("\ndecision:", JSON.stringify(decision, null, 2));

  // Read it back — no outbound call. This proves the audit row was actually
  // written, which is where a stale map ACL shows up.
  const stored = await agent.client.executeAndDecode({
    contract_id: contractId,
    contract_version: contractVersion,
    function_name: "get-check",
    input: { "subject-ref": subjectRef },
  });
  console.log("\naudit row:", JSON.stringify(stored, null, 2));

  if (!JSON.stringify(stored).includes(subjectRef)) {
    throw new Error("audit row did not round-trip — check the map ACLs");
  }
  console.log(
    "\nrun-check OK — decision recorded and read back, no PII in either payload",
  );
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
