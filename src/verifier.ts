/**
 * Proof verifiers.
 *
 * A Verifier turns a ProofBundle into a boolean. There are two implementations:
 *
 *   sorobanVerifier — REAL. Calls the deployed Groth16 verifier contract on
 *     Stellar via Soroban RPC (BN254 pairing host functions, CAP-0074). This is
 *     the production path. Wired in Phase 2 once the contract is deployed.
 *
 *   devVerifier — TEMPORARY SCAFFOLD, dev-only. Checks an HMAC tag instead of a
 *     real SNARK so the end-to-end flow runs before the circuit/contract exist.
 *     It is NOT cryptographically meaningful and refuses to run unless explicitly
 *     opted in. Delete once sorobanVerifier is live.
 */

import type { ProofBundle } from "./types.js";
import { fieldToBytes, g1ToBytes, g2ToBytes } from "./encoding.js";

export interface Verifier {
  readonly mode: "soroban" | "local" | "dev";
  /** Returns true iff the proof is valid for its public signals. Must NOT do
   *  policy checks (price/recipient/replay) — those live in the gate. */
  verify(bundle: ProofBundle): Promise<boolean>;
}

/** Public-signal array in the circuit's fixed order. Used by every real verifier
 *  and must match payment.circom's `main {public [...]}` list. */
export function publicSignalArray(bundle: ProofBundle): string[] {
  const s = bundle.publicSignals;
  return [s.nullifier, s.merkleRoot, s.payTo, s.requiredAmount, s.contextHash];
}

// ── REAL: on-chain Groth16 verification via Soroban ──────────────────────────

export interface SorobanVerifierConfig {
  /** Soroban RPC endpoint, e.g. https://soroban-testnet.stellar.org */
  rpcUrl: string;
  network: "testnet" | "mainnet" | "futurenet" | "local";
  /** Deployed null-402 verifier contract id (C...), already `init`-ed with the vk. */
  verifierContractId: string;
  /** A funded account public key used ONLY to simulate (read-only; never signs). */
  sourceAccount: string;
  /** Network passphrase override (defaults derived from `network`). */
  networkPassphrase?: string;
}

/**
 * Verify the Groth16 proof by simulating `verify(proof, public_inputs)` on the
 * deployed verifier contract over Soroban RPC. The BN254 pairing check runs
 * on-chain, so trust is anchored on Stellar — this SDK only encodes args and
 * reads the boolean. Read-only: no fee, no signature, no state change.
 *
 * Requires `@stellar/stellar-sdk` (optional peer dep). The proof must be a
 * snarkjs Groth16 proof object (pi_a/pi_b/pi_c), as produced by `groth16Prover`.
 */
export function sorobanVerifier(cfg: SorobanVerifierConfig): Verifier {
  return {
    mode: "soroban",
    async verify(bundle: ProofBundle): Promise<boolean> {
      const sdk = await loadStellarSdk();
      const { rpc, Contract, TransactionBuilder, scValToNative, Networks, BASE_FEE, xdr } = sdk;

      const server = new rpc.Server(cfg.rpcUrl, { allowHttp: cfg.rpcUrl.startsWith("http://") });
      const source = await server.getAccount(cfg.sourceAccount);
      const contract = new Contract(cfg.verifierContractId);

      // Build the ScVals explicitly: the Proof struct is a map with SYMBOL keys
      // (a,b,c) → bytes; public_inputs is a vec of bytes. (nativeToScVal encodes
      // object keys as strings, which the contract rejects with UnexpectedType.)
      const sym = (s: string) => xdr.ScVal.scvSymbol(s);
      const bytes = (u: Uint8Array) => xdr.ScVal.scvBytes(toBuf(u));
      const p = bundle.proof as { pi_a: string[]; pi_b: string[][]; pi_c: string[] };
      const proofScVal = xdr.ScVal.scvMap([
        new xdr.ScMapEntry({ key: sym("a"), val: bytes(g1ToBytes(p.pi_a)) }),
        new xdr.ScMapEntry({ key: sym("b"), val: bytes(g2ToBytes(p.pi_b)) }),
        new xdr.ScMapEntry({ key: sym("c"), val: bytes(g1ToBytes(p.pi_c)) }),
      ]);
      const publicScVal = xdr.ScVal.scvVec(
        publicSignalArray(bundle).map((s) => bytes(fieldToBytes(s))),
      );

      const passphrase =
        cfg.networkPassphrase ??
        (cfg.network === "mainnet"
          ? Networks.PUBLIC
          : cfg.network === "futurenet"
            ? Networks.FUTURENET
            : Networks.TESTNET);

      const tx = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: passphrase })
        .addOperation(contract.call("verify", proofScVal, publicScVal))
        .setTimeout(30)
        .build();

      const sim = await server.simulateTransaction(tx);
      if (rpc.Api.isSimulationError(sim) || !sim.result?.retval) return false;
      return scValToNative(sim.result.retval) === true;
    },
  };
}

/** Node/Workers Buffer (runtime), without depending on @types/node at build time. */
const toBuf = (u: Uint8Array): any => (globalThis as any).Buffer.from(u);

/** Dynamically load @stellar/stellar-sdk (optional dep, indirect specifier). */
export async function loadStellarSdk(): Promise<any> {
  const spec = "@stellar/stellar-sdk";
  const m: any = await import(spec);
  const sdk = m?.rpc ? m : m?.default;
  if (!sdk?.rpc) {
    throw new Error("@stellar/stellar-sdk is required for sorobanVerifier. Install it: npm i @stellar/stellar-sdk");
  }
  return sdk;
}

// ── REAL: off-chain Groth16 verification via snarkjs ─────────────────────────

/**
 * Verify the Groth16 proof off-chain with snarkjs against the circuit's verifying
 * key. This is REAL zero-knowledge verification — the same pairing check the
 * Soroban contract performs, just run locally. Use it where there is no chain
 * access (tests, edge environments) or as a fast pre-check before sorobanVerifier.
 *
 * Requires `snarkjs` (optional peer dep) and the circuit's verification_key.json.
 */
export function localGroth16Verifier(opts: { verificationKey: object }): Verifier {
  return {
    mode: "local",
    async verify(bundle: ProofBundle): Promise<boolean> {
      const snarkjs = await loadSnarkjs();
      try {
        return await snarkjs.groth16.verify(
          opts.verificationKey,
          publicSignalArray(bundle),
          bundle.proof,
        );
      } catch {
        return false;
      }
    },
  };
}

/** Dynamically load snarkjs (CJS or ESM interop) so it stays an optional dep.
 *  Indirect specifier keeps TS/bundlers from resolving it at build time. */
export async function loadSnarkjs(): Promise<any> {
  const spec = "snarkjs";
  const m: any = await import(spec);
  const snarkjs = m?.groth16 ? m : m?.default;
  if (!snarkjs?.groth16) {
    throw new Error("snarkjs is required for real Groth16 proving/verification. Install it: npm i snarkjs");
  }
  return snarkjs;
}

// ── TEMPORARY: dev scaffold (NOT real ZK) ────────────────────────────────────

/**
 * Dev-only verifier. Recomputes an HMAC-SHA256 tag over the public signals with
 * a shared secret and compares it to `bundle.proof`. Lets the gateway + client
 * agree on a valid-shaped exchange before the real circuit exists.
 *
 * Guardrails: throws unless `allowInsecure` is true. Production code paths must
 * never construct this.
 */
export function devVerifier(opts: { sharedSecret: string; allowInsecure: boolean }): Verifier {
  if (!opts.allowInsecure) {
    throw new Error(
      "devVerifier is an insecure scaffold and is disabled. Pass allowInsecure:true " +
        "ONLY in local/dev, or switch to sorobanVerifier for real ZK verification.",
    );
  }
  return {
    mode: "dev",
    async verify(bundle: ProofBundle): Promise<boolean> {
      const expected = await devTag(opts.sharedSecret, bundle.publicSignals);
      return typeof bundle.proof === "string" && timingSafeEqual(bundle.proof, expected);
    },
  };
}

/** Shared dev tag used by both devVerifier and the dev prover in client.ts. */
export async function devTag(
  secret: string,
  signals: ProofBundle["publicSignals"],
): Promise<string> {
  const enc = new TextEncoder();
  const msg = [
    signals.nullifier,
    signals.merkleRoot,
    signals.payTo,
    signals.requiredAmount,
    signals.contextHash,
  ].join("|");
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
