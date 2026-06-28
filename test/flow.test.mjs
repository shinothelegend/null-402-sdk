/**
 * End-to-end flow test for the null-402 SDK (Phase 1, dev verifier).
 *
 * Proves the private-payment logic without any chain or circuit:
 *   client deposits → proves locally → gateway verifies → accepts,
 *   and every failure mode (replay, wrong recipient, insufficient amount,
 *   context mismatch, tampered proof, missing payment) is rejected.
 *
 * Run: npm test   (after npm run build)
 */

import assert from "node:assert/strict";
import { verifyPayment, memoryNullifierStore, devVerifier } from "../dist/server.js";
import { Null402Client, devProver } from "../dist/client.js";
import { encodePayment } from "../dist/proof.js";

const SECRET = "test-shared-secret";
const PAYTO = "GADEMOGATEWAYACCOUNT_TEST";
const ROOT = "0xpoolroot";
const PRICE = 1_000;
const PATH = "/v1/price/BTC";

const client = new Null402Client({ prover: devProver({ sharedSecret: SECRET }) });

function gate(overrides = {}) {
  return {
    requiredAmount: PRICE,
    payTo: PAYTO,
    verifier: devVerifier({ sharedSecret: SECRET, allowInsecure: true }),
    nullifiers: memoryNullifierStore(),
    ...overrides,
  };
}

async function makeHeader({ payTo = PAYTO, requiredAmount = PRICE, path = PATH } = {}) {
  const note = await client.deposit(10_000n);
  const bundle = await client.prove({
    note,
    merkleRoot: ROOT,
    payTo,
    requiredAmount,
    request: { method: "GET", path },
  });
  return { header: encodePayment(bundle), bundle };
}

let passed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}\n    ${err.message}`);
    process.exitCode = 1;
  }
}

console.log("null-402 SDK — end-to-end flow");

await test("happy path: valid proof is accepted", async () => {
  const { header } = await makeHeader();
  const out = await verifyPayment({ method: "GET", path: PATH, paymentHeader: header }, gate());
  assert.equal(out.ok, true);
  assert.equal(out.result.valid, true);
  assert.equal(out.result.mode, "dev");
});

await test("replay: same nullifier twice is rejected", async () => {
  const cfg = gate(); // shared store across both calls
  const { header } = await makeHeader();
  const first = await verifyPayment({ method: "GET", path: PATH, paymentHeader: header }, cfg);
  assert.equal(first.ok, true);
  const second = await verifyPayment({ method: "GET", path: PATH, paymentHeader: header }, cfg);
  assert.equal(second.ok, false);
  assert.equal(second.reason, "replay");
});

await test("missing payment → no-payment (triggers 402)", async () => {
  const out = await verifyPayment({ method: "GET", path: PATH, paymentHeader: null }, gate());
  assert.equal(out.ok, false);
  assert.equal(out.reason, "no-payment");
});

await test("wrong recipient is rejected", async () => {
  const { header } = await makeHeader({ payTo: "GSOMEONEELSE_TEST" });
  const out = await verifyPayment({ method: "GET", path: PATH, paymentHeader: header }, gate());
  assert.equal(out.ok, false);
  assert.equal(out.reason, "wrong-recipient");
});

await test("insufficient amount is rejected", async () => {
  // Client proves it covers PRICE, but the gate demands more.
  const { header } = await makeHeader({ requiredAmount: PRICE });
  const out = await verifyPayment(
    { method: "GET", path: PATH, paymentHeader: header },
    gate({ requiredAmount: PRICE * 2 }),
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "insufficient-amount");
});

await test("context mismatch (different endpoint) is rejected", async () => {
  const { header } = await makeHeader({ path: "/v1/price/BTC" });
  const out = await verifyPayment(
    { method: "GET", path: "/v1/price/ETH", paymentHeader: header },
    gate(),
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "context-mismatch");
});

await test("tampered proof is rejected (and nullifier rolled back)", async () => {
  const { bundle } = await makeHeader();
  const tampered = { ...bundle, proof: bundle.proof.slice(0, -1) + (bundle.proof.endsWith("0") ? "1" : "0") };
  const cfg = gate();
  const out = await verifyPayment(
    { method: "GET", path: PATH, paymentHeader: encodePayment(tampered) },
    cfg,
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "invalid-proof");
  // nullifier must be free again so a legit retry could work
  assert.equal(await cfg.nullifiers.has(tampered.publicSignals.nullifier), false);
});

console.log(`\n${passed}/7 checks passed`);
if (process.exitCode) console.error("FAILED");
else console.log("ALL PASS");
