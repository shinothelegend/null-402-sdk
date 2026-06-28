/**
 * REAL zero-knowledge end-to-end test (no chain, no scaffold).
 *
 *   client.deposit → groth16Prover (snarkjs + circuit) → real Groth16 proof
 *   → verifyPayment with localGroth16Verifier (real snarkjs pairing check).
 *
 * Requires the null-402-circuits artifacts (run `npm run build` there first).
 * Skips cleanly if they're absent.
 *
 * Run: npm run test:real
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildPoseidon } from "circomlibjs";
import { Null402Client, groth16Prover } from "../dist/client.js";
import { verifyPayment, memoryNullifierStore, localGroth16Verifier } from "../dist/server.js";

const B = (u) => fileURLToPath(new URL(u, import.meta.url));
const wasmPath = B("../../null-402-circuits/build/payment_js/payment.wasm");
const zkeyPath = B("../../null-402-circuits/build/payment.zkey");
const vkeyPath = B("../../null-402-circuits/build/verification_key.json");

if (!existsSync(zkeyPath) || !existsSync(wasmPath) || !existsSync(vkeyPath)) {
  console.log("⚠ circuit artifacts not found — run `npm run build` in null-402-circuits first. Skipping.");
  process.exit(0);
}

const LEVELS = 20;
const PAYTO = "GREALTESTGATEWAYACCOUNT";
const PATH = "/v1/price/BTC";
const PRICE = 1000;

const verificationKey = JSON.parse(readFileSync(vkeyPath, "utf8"));
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P = (arr) => F.toObject(poseidon(arr)); // -> BigInt

// Build the empty-subtree Merkle path for a commitment placed at leaf index 0.
function treeFor(commitment) {
  const zeros = [0n];
  for (let i = 1; i < LEVELS; i++) zeros[i] = P([zeros[i - 1], zeros[i - 1]]);
  const pathElements = [];
  const pathIndices = [];
  let cur = commitment;
  for (let i = 0; i < LEVELS; i++) {
    pathElements.push(zeros[i].toString());
    pathIndices.push(0);
    cur = P([cur, zeros[i]]);
  }
  return { pathElements, pathIndices, merkleRoot: cur.toString() };
}

const client = new Null402Client({ prover: groth16Prover({ wasmPath, zkeyPath }) });

let passed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}\n    ${err.stack || err.message}`);
    process.exitCode = 1;
  }
}

console.log("null-402 SDK — REAL Groth16 proof end-to-end");

// Shared: mint a note, build its tree, generate a real proof for the request.
async function provePayment() {
  const note = await client.deposit(5000n); // value 5000 >= price 1000
  const commitment = P([BigInt(note.secret), BigInt(note.nullifierSecret), note.value]);
  const { pathElements, pathIndices, merkleRoot } = treeFor(commitment);
  const bundle = await client.prove({
    note,
    merkleRoot,
    payTo: PAYTO,
    requiredAmount: PRICE,
    request: { method: "GET", path: PATH },
    pathElements,
    pathIndices,
  });
  return { bundle, merkleRoot };
}

let cached;

await test("client generates a real Groth16 proof that snarkjs verifies", async () => {
  cached = await provePayment();
  const verifier = localGroth16Verifier({ verificationKey });
  assert.equal(await verifier.verify(cached.bundle), true, "proof should verify");
});

await test("verifyPayment accepts the real proof (mode=local)", async () => {
  const { bundle, merkleRoot } = cached;
  const out = await verifyPayment(
    { method: "GET", path: PATH, paymentHeader: encode(bundle) },
    {
      requiredAmount: PRICE,
      payTo: PAYTO,
      verifier: localGroth16Verifier({ verificationKey }),
      nullifiers: memoryNullifierStore(),
      isKnownRoot: async (r) => r === merkleRoot,
    },
  );
  assert.equal(out.ok, true, out.ok ? "" : `rejected: ${out.reason}`);
  assert.equal(out.result.mode, "local");
});

await test("a tampered proof is rejected by the real verifier", async () => {
  const { bundle } = await provePayment();
  const bad = JSON.parse(JSON.stringify(bundle));
  bad.proof.pi_a[0] = (BigInt(bad.proof.pi_a[0]) + 1n).toString(); // corrupt one coordinate
  const verifier = localGroth16Verifier({ verificationKey });
  assert.equal(await verifier.verify(bad), false);
});

await test("wrong required amount fails membership/range (proof won't generate)", async () => {
  // value 500 < price 1000 -> circuit's GreaterEqThan constraint is unsatisfiable
  const note = await client.deposit(500n);
  const commitment = P([BigInt(note.secret), BigInt(note.nullifierSecret), note.value]);
  const { pathElements, pathIndices, merkleRoot } = treeFor(commitment);
  await assert.rejects(
    client.prove({
      note, merkleRoot, payTo: PAYTO, requiredAmount: PRICE,
      request: { method: "GET", path: PATH }, pathElements, pathIndices,
    }),
    "proving an underfunded note must fail",
  );
});

console.log(`\n${passed}/4 checks passed`);
console.log(process.exitCode ? "FAILED" : "ALL PASS");

// local import to avoid pulling proof.ts encode at top (keep imports tidy)
function encode(bundle) {
  const json = JSON.stringify(bundle);
  const b64 = Buffer.from(json, "utf8").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
