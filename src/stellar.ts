/**
 * On-chain Soroban helpers for the null-402 pool — these make the economic loop
 * REAL: the agent escrows actual XLM (`poolDeposit`) and the operator moves
 * actual XLM on settlement (`poolSettle`). Uses @stellar/stellar-sdk (optional
 * peer dep, loaded via indirect specifier).
 */

import type { ProofBundle } from "./types.js";
import { fieldToBytes, g1ToBytes, g2ToBytes } from "./encoding.js";
import { publicSignalArray } from "./verifier.js";

const PASSPHRASE: Record<string, string> = {
  testnet: "Test SDF Network ; September 2015",
  mainnet: "Public Global Stellar Network ; September 2015",
  futurenet: "Test SDF Future Network ; October 2022",
  local: "Standalone Network ; February 2017",
};

export interface PoolConfig {
  rpcUrl: string;
  network: "testnet" | "mainnet" | "futurenet" | "local";
  poolContractId: string;
}

const toBuf = (u: Uint8Array): any => (globalThis as any).Buffer.from(u);

async function loadSdk(): Promise<any> {
  const spec = "@stellar/stellar-sdk";
  const m: any = await import(spec);
  const sdk = m?.rpc ? m : m?.default;
  if (!sdk?.rpc) throw new Error("@stellar/stellar-sdk required. Install it: npm i @stellar/stellar-sdk");
  return sdk;
}

/** prepare → sign → send → poll. Returns the tx hash + the final response.
 *  Retries the prepare/simulate step through transient RPC state-lag (a just-
 *  confirmed deposit's balance/storage can take a few seconds to be visible to
 *  the simulate node). */
async function submit(server: any, S: any, tx: any, secret: string): Promise<{ hash: string; returnValue: any }> {
  let prepared: any;
  for (let attempt = 1; ; attempt++) {
    try {
      prepared = await server.prepareTransaction(tx);
      break;
    } catch (e) {
      if (attempt >= 6) throw e;
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  prepared.sign(S.Keypair.fromSecret(secret));
  const sent = await server.sendTransaction(prepared);
  if (sent.status === "ERROR") {
    throw new Error("sendTransaction ERROR: " + JSON.stringify(sent.errorResult ?? sent));
  }
  const hash = sent.hash;
  let res = await server.getTransaction(hash);
  for (let i = 0; i < 40 && res.status === "NOT_FOUND"; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    res = await server.getTransaction(hash);
  }
  if (res.status !== "SUCCESS") throw new Error(`tx ${hash} status=${res.status}`);
  return { hash, returnValue: res.returnValue };
}

/** Agent escrows `amount` (stroops) and records `commitment` (decimal field). */
export async function poolDeposit(
  opts: PoolConfig & { signerSecret: string; commitment: string; amount: bigint },
): Promise<{ hash: string; leafIndex: number }> {
  const S = await loadSdk();
  const server = new S.rpc.Server(opts.rpcUrl, { allowHttp: opts.rpcUrl.startsWith("http://") });
  const kp = S.Keypair.fromSecret(opts.signerSecret);
  const from = kp.publicKey();
  const account = await server.getAccount(from);
  const op = new S.Contract(opts.poolContractId).call(
    "deposit",
    new S.Address(from).toScVal(),
    S.xdr.ScVal.scvBytes(toBuf(fieldToBytes(opts.commitment))),
    S.nativeToScVal(opts.amount, { type: "i128" }),
  );
  const tx = new S.TransactionBuilder(account, { fee: S.BASE_FEE, networkPassphrase: PASSPHRASE[opts.network] })
    .addOperation(op)
    .setTimeout(60)
    .build();
  const { hash, returnValue } = await submit(server, S, tx, opts.signerSecret);
  const leafIndex = returnValue ? Number(S.scValToNative(returnValue)) : 0;
  return { hash, leafIndex };
}

/** Read the pool's on-chain commitment list (decimal field strings). Read-only. */
export async function poolCommitments(
  opts: PoolConfig & { sourceAccount: string },
): Promise<string[]> {
  const S = await loadSdk();
  const server = new S.rpc.Server(opts.rpcUrl, { allowHttp: opts.rpcUrl.startsWith("http://") });
  const account = await server.getAccount(opts.sourceAccount);
  const tx = new S.TransactionBuilder(account, { fee: S.BASE_FEE, networkPassphrase: PASSPHRASE[opts.network] })
    .addOperation(new S.Contract(opts.poolContractId).call("commitments"))
    .setTimeout(30)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (S.rpc.Api.isSimulationError(sim) || !sim.result?.retval) return [];
  const arr = S.scValToNative(sim.result.retval) as Uint8Array[];
  return arr.map((u) => {
    let n = 0n;
    for (const b of u) n = (n << 8n) | BigInt(b);
    return n.toString();
  });
}

/** Operator settles a verified payment: on-chain Groth16 verify → spend nullifier
 *  → pay `recipient` (stroops). Returns the settlement tx hash. */
export async function poolSettle(
  opts: PoolConfig & { operatorSecret: string; bundle: ProofBundle; recipient: string; amount: bigint },
): Promise<{ hash: string }> {
  const S = await loadSdk();
  const server = new S.rpc.Server(opts.rpcUrl, { allowHttp: opts.rpcUrl.startsWith("http://") });
  const kp = S.Keypair.fromSecret(opts.operatorSecret);
  const account = await server.getAccount(kp.publicKey());
  const p = opts.bundle.proof as { pi_a: string[]; pi_b: string[][]; pi_c: string[] };
  const sym = (s: string) => S.xdr.ScVal.scvSymbol(s);
  const bytes = (u: Uint8Array) => S.xdr.ScVal.scvBytes(toBuf(u));
  const proofScVal = S.xdr.ScVal.scvMap([
    new S.xdr.ScMapEntry({ key: sym("a"), val: bytes(g1ToBytes(p.pi_a)) }),
    new S.xdr.ScMapEntry({ key: sym("b"), val: bytes(g2ToBytes(p.pi_b)) }),
    new S.xdr.ScMapEntry({ key: sym("c"), val: bytes(g1ToBytes(p.pi_c)) }),
  ]);
  const pubScVal = S.xdr.ScVal.scvVec(publicSignalArray(opts.bundle).map((s) => bytes(fieldToBytes(s))));
  const op = new S.Contract(opts.poolContractId).call(
    "settle",
    proofScVal,
    pubScVal,
    new S.Address(opts.recipient).toScVal(),
    S.nativeToScVal(opts.amount, { type: "i128" }),
  );
  const tx = new S.TransactionBuilder(account, { fee: S.BASE_FEE, networkPassphrase: PASSPHRASE[opts.network] })
    .addOperation(op)
    .setTimeout(60)
    .build();
  const { hash } = await submit(server, S, tx, opts.operatorSecret);
  return { hash };
}
