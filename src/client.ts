/**
 * null-402 client SDK — the part a paying app/agent uses.
 *
 *   1. deposit(amount)        — fund a private note in the Pool (Phase 2: signs a
 *                               Soroban tx; returns the note secret to keep).
 *   2. prove({ terms })       — generate a payment proof for a request, locally.
 *   3. pay(url, init)         — fetch() that auto-handles 402: read terms, prove,
 *                               retry with the X-PAYMENT header. Secrets never
 *                               leave this process.
 */

import type { ProofBundle, PaymentPublicSignals, StellarConfig } from "./types.js";
import { contextPreimage, hashContext, encodePayment, addressToField } from "./proof.js";
import { devTag, loadSnarkjs } from "./verifier.js";

/** A spendable private note held by the client (kept secret, never sent). */
export interface Note {
  /** Random secret that, with `nullifierSecret`, derives the commitment + nullifier. */
  secret: string;
  nullifierSecret: string;
  /** Note value in base units. */
  value: bigint;
  /** Leaf index / commitment as known to the Pool (set after deposit confirms). */
  commitment?: string;
  leafIndex?: number;
}

/** Pluggable prover so the dev scaffold and the real snarkjs prover share an API. */
export interface Prover {
  readonly mode: "groth16" | "dev";
  prove(input: ProverInput): Promise<ProofBundle>;
}

export interface ProverInput {
  note: Note;
  merkleRoot: string;
  /** Merkle membership path from the Pool (required by the real prover). */
  pathElements?: string[];
  pathIndices?: number[];
  /** Field-encoded recipient (see addressToField). */
  payTo: string;
  requiredAmount: string;
  /** Field-encoded request binding (see hashContext). */
  contextHash: string;
}

export interface Null402ClientOptions {
  stellar?: StellarConfig;
  prover: Prover;
}

export class Null402Client {
  constructor(private readonly opts: Null402ClientOptions) {}

  /**
   * Deposit funds into the Pool, creating a private note.
   * Phase 2: builds + signs the Pool `deposit(commitment, amount)` Soroban tx and
   * waits for the leaf index. For now it mints a local note so the flow runs.
   */
  async deposit(value: bigint, rng: () => string = randomField): Promise<Note> {
    return { secret: rng(), nullifierSecret: rng(), value };
  }

  /** Generate a payment proof bound to a specific request + terms. */
  async prove(args: {
    note: Note;
    merkleRoot: string;
    payTo: string;
    requiredAmount: string | number;
    request: { method: string; path: string };
    pathElements?: string[];
    pathIndices?: number[];
  }): Promise<ProofBundle> {
    const contextHash = await hashContext(
      contextPreimage({
        method: args.request.method,
        path: args.request.path,
        requiredAmount: args.requiredAmount,
        payTo: args.payTo,
      }),
    );
    return this.opts.prover.prove({
      note: args.note,
      merkleRoot: args.merkleRoot,
      pathElements: args.pathElements,
      pathIndices: args.pathIndices,
      payTo: await addressToField(args.payTo),
      requiredAmount: String(args.requiredAmount),
      contextHash,
    });
  }

  /**
   * fetch() wrapper that transparently satisfies a 402. Pass the note to spend
   * and the current Pool merkleRoot; on a 402 it proves + retries once.
   */
  async pay(
    url: string,
    init: (RequestInit & {
      note: Note;
      merkleRoot: string;
      pathElements?: string[];
      pathIndices?: number[];
    }),
  ): Promise<Response> {
    const { note, merkleRoot, pathElements, pathIndices, ...reqInit } = init;
    const first = await fetch(url, reqInit);
    if (first.status !== 402) return first;

    const u = new URL(url);
    const bundle = await this.prove({
      note,
      merkleRoot,
      pathElements,
      pathIndices,
      payTo: await payToFrom402(first),
      requiredAmount: await requiredAmountFrom402(first),
      request: { method: (reqInit.method ?? "GET").toUpperCase(), path: u.pathname },
    });

    return fetch(url, {
      ...reqInit,
      headers: { ...(reqInit.headers ?? {}), "X-PAYMENT": encodePayment(bundle) },
    });
  }
}

// ── Provers ───────────────────────────────────────────────────────────────────

/**
 * REAL prover: generates a Groth16 witness + proof with snarkjs against the
 * null-402-circuits artifacts (payment.wasm + payment.zkey). Computes the
 * nullifier = Poseidon(nullifierSecret) in-process and proves note membership +
 * value >= requiredAmount + recipient/request binding. Secrets never leave here.
 *
 * Requires the Merkle path (pathElements + pathIndices) for the note's leaf,
 * obtained from the Pool. Requires `snarkjs` + `circomlibjs` (optional peer deps).
 */
export function groth16Prover(artifacts: { wasmPath: string; zkeyPath: string }): Prover {
  return {
    mode: "groth16",
    async prove(input: ProverInput): Promise<ProofBundle> {
      if (!input.pathElements || !input.pathIndices) {
        throw new Error("groth16Prover requires Merkle pathElements + pathIndices (from the Pool).");
      }
      const snarkjs = await loadSnarkjs();
      const poseidon = await loadPoseidon();

      const nullifierSecret = BigInt(input.note.nullifierSecret);
      const nullifier = poseidon.F.toObject(poseidon([nullifierSecret])).toString();

      const circuitInput = {
        noteSecret: BigInt(input.note.secret).toString(),
        nullifierSecret: nullifierSecret.toString(),
        noteValue: input.note.value.toString(),
        pathElements: input.pathElements,
        pathIndices: input.pathIndices,
        nullifier,
        merkleRoot: input.merkleRoot,
        payTo: input.payTo,
        requiredAmount: input.requiredAmount,
        contextHash: input.contextHash,
      };

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput,
        artifacts.wasmPath,
        artifacts.zkeyPath,
      );

      // publicSignals order: [nullifier, merkleRoot, payTo, requiredAmount, contextHash]
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
    },
  };
}

/**
 * TEMPORARY dev prover. Produces a valid-shaped bundle whose `proof` is the HMAC
 * tag devVerifier expects. NOT real ZK — `allowInsecure` must match the gate.
 */
export function devProver(opts: { sharedSecret: string }): Prover {
  return {
    mode: "dev",
    async prove(input: ProverInput): Promise<ProofBundle> {
      const nullifier = await sha256Hex(`${input.note.secret}:${input.note.nullifierSecret}`);
      const signals: PaymentPublicSignals = {
        nullifier,
        merkleRoot: input.merkleRoot,
        payTo: input.payTo,
        requiredAmount: input.requiredAmount,
        contextHash: input.contextHash,
      };
      const proof = await devTag(opts.sharedSecret, signals);
      return { proof, publicSignals: signals };
    },
  };
}

/**
 * Build the proof inputs (commitment, Merkle path, root) for a note deposited at
 * leaf index 0 of an otherwise-empty Poseidon tree. Useful for the first deposit
 * and for tests; in production a client gets its path from the Pool's commitment
 * list (computed off-chain by the gateway/indexer, since Stellar has no on-chain
 * Poseidon yet).
 */
export async function emptyPoolWitness(
  note: Note,
  levels = 20,
): Promise<{ commitment: string; pathElements: string[]; pathIndices: number[]; merkleRoot: string }> {
  const poseidon = await loadPoseidon();
  const F = poseidon.F;
  const H = (arr: bigint[]): bigint => F.toObject(poseidon(arr));

  const commitment = H([BigInt(note.secret), BigInt(note.nullifierSecret), note.value]);

  const zeros: bigint[] = [0n];
  let z = 0n;
  for (let i = 1; i < levels; i++) {
    z = H([z, z]);
    zeros.push(z);
  }

  const pathElements: string[] = [];
  const pathIndices: number[] = [];
  let cur = commitment;
  for (let i = 0; i < levels; i++) {
    const sib = zeros[i] ?? 0n;
    pathElements.push(sib.toString());
    pathIndices.push(0);
    cur = H([cur, sib]);
  }
  return { commitment: commitment.toString(), pathElements, pathIndices, merkleRoot: cur.toString() };
}

// ── helpers ─────────────────────────────────────────────────────────────────

/** Random BN254 field element (decimal string) — note secrets live in the field. */
function randomField(): string {
  const b = crypto.getRandomValues(new Uint8Array(31)); // < 2^248 < field modulus
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n.toString();
}

/** Dynamically load circomlibjs Poseidon (optional dep) for nullifier derivation. */
async function loadPoseidon(): Promise<any> {
  const spec = "circomlibjs";
  const m: any = await import(spec);
  const build = m?.buildPoseidon ?? m?.default?.buildPoseidon;
  if (!build) {
    throw new Error("circomlibjs is required for real proving. Install it: npm i circomlibjs");
  }
  return build();
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function payToFrom402(res: Response): Promise<string> {
  const j = (await res.clone().json()) as { accepts?: Array<{ payTo: string }> };
  const pay = j.accepts?.[0]?.payTo;
  if (!pay) throw new Error("402 response missing accepts[0].payTo");
  return pay;
}

async function requiredAmountFrom402(res: Response): Promise<string> {
  const j = (await res.clone().json()) as { accepts?: Array<{ maxAmountRequired: string }> };
  const amt = j.accepts?.[0]?.maxAmountRequired;
  if (!amt) throw new Error("402 response missing accepts[0].maxAmountRequired");
  return amt;
}
