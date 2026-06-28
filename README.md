# null-402

> Private pay-per-call on Stellar. x402, but the payment is a zero-knowledge
> proof — no wallet, amount, or endpoint is revealed on-chain or to the gateway.

Any API provider can accept private payments in a few lines. Any client can pay
without leaking who they are, what they paid, or what they called.

## Server — gate an endpoint

```ts
import { verifyPayment, build402, sorobanVerifier, memoryNullifierStore } from "null-402/server";

const cfg = {
  requiredAmount: 1_000,                       // price tier
  payTo: "G...GATEWAY",                         // your Stellar account/contract
  verifier: sorobanVerifier({ rpcUrl, network: "testnet", poolContractId, verifierContractId }),
  nullifiers: memoryNullifierStore(),           // swap for KV / Durable Object / DB
};

const out = await verifyPayment(
  { method: req.method, path: url.pathname, paymentHeader: req.headers.get("X-PAYMENT") },
  cfg,
);
if (!out.ok) { /* 402 via build402(...) or 4xx with out.reason */ }
else { /* serve the resource — out.result.valid === true */ }
```

## Client — pay privately

```ts
import { Null402Client, groth16Prover } from "null-402/client";

const client = new Null402Client({
  stellar: { rpcUrl, network: "testnet", poolContractId, verifierContractId },
  prover: groth16Prover({ wasmPath, zkeyPath }),
});

const note = await client.deposit(10_000n);     // one-time, funds the pool
const res = await client.pay("https://api.example.com/v1/price/BTC", {
  note, merkleRoot, method: "GET",
});                                              // handles 402 → prove → retry
```

## How it works

```
deposit → private note (Poseidon commitment in the Pool's Merkle tree)
call    → Groth16 proof: "I own an unspent note ≥ price, bound to THIS request"
verify  → Soroban verifier contract returns valid:bool; nullifier blocks replay
```

Verifier / Policy / Application are split: the verifier checks only cryptographic
validity, the gate enforces recipient + amount tier + request binding + replay,
your app runs only after both pass.

## Phase 1 vs Phase 2

- `devVerifier` / `devProver` are an **insecure** local scaffold so the flow runs
  before the circuit/contracts exist. They require `allowInsecure: true` and must
  never be used in production.
- `sorobanVerifier` / `groth16Prover` are the real path — wired once
  `packages/circuits` and `packages/contracts` are built and deployed.

MIT.
