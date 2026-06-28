/**
 * LIVE on-chain test: the SDK's sorobanVerifier verifies a real proof against the
 * deployed null-402 verifier contract on Stellar testnet (read-only simulate).
 *
 * Defaults target the deployed testnet contract; override with env:
 *   NULL402_RPC, NULL402_VERIFIER_ID, NULL402_SOURCE
 *
 * Requires the circuits artifacts (build/proof.json, build/public.json) and
 * network access. Skips cleanly if either is missing/unreachable.
 *
 * Run: npm run test:soroban
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sorobanVerifier } from "../dist/index.js";

const B = (u) => fileURLToPath(new URL(u, import.meta.url));
const proofPath = B("../../null-402-circuits/build/proof.json");
const publicPath = B("../../null-402-circuits/build/public.json");

if (!existsSync(proofPath) || !existsSync(publicPath)) {
  console.log("⚠ circuit proof artifacts not found — run the circuits build first. Skipping.");
  process.exit(0);
}

const RPC = process.env.NULL402_RPC ?? "https://soroban-testnet.stellar.org";
const VERIFIER_ID =
  process.env.NULL402_VERIFIER_ID ?? "CDCYYFSJ7QC7RO6L2DHWK6X6IMZ5U5J3IEAKLKTBTBDX45LWO32JQJLV";
const SOURCE =
  process.env.NULL402_SOURCE ?? "GCCNVKTTTRIINEBPH7LPERQ7KSJYEP7ZCDMH2A62Z7IJTDBZ4LHMPEYW";

const proof = JSON.parse(readFileSync(proofPath, "utf8"));
const pub = JSON.parse(readFileSync(publicPath, "utf8")); // [nullifier, merkleRoot, payTo, requiredAmount, contextHash]

function bundle(publicSignals) {
  return {
    proof,
    publicSignals: {
      nullifier: publicSignals[0],
      merkleRoot: publicSignals[1],
      payTo: publicSignals[2],
      requiredAmount: publicSignals[3],
      contextHash: publicSignals[4],
    },
  };
}

const verifier = sorobanVerifier({
  rpcUrl: RPC,
  network: "testnet",
  verifierContractId: VERIFIER_ID,
  sourceAccount: SOURCE,
});

let passed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    if (/fetch|network|ENOTFOUND|getaddrinfo|timeout|account not found/i.test(String(err.message))) {
      console.log(`  ⚠ ${name} — network/contract unavailable, skipping (${err.message})`);
      return;
    }
    console.error(`  ✗ ${name}\n    ${err.stack || err.message}`);
    process.exitCode = 1;
  }
}

console.log(`null-402 SDK — sorobanVerifier vs testnet contract ${VERIFIER_ID.slice(0, 8)}…`);

await test("real proof verifies on-chain (mode=soroban)", async () => {
  assert.equal(verifier.mode, "soroban");
  assert.equal(await verifier.verify(bundle(pub)), true);
});

await test("tampered public input is rejected on-chain", async () => {
  const bad = [...pub];
  bad[0] = (BigInt(bad[0]) + 1n).toString();
  assert.equal(await verifier.verify(bundle(bad)), false);
});

console.log(`\n${passed}/2 checks passed`);
console.log(process.exitCode ? "FAILED" : "DONE");
