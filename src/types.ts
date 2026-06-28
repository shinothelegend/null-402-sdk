/**
 * null-402 — shared types for private pay-per-call on Stellar.
 *
 * The privacy model: a client proves it owns an unspent note in the null-402
 * shielded Pool worth >= the endpoint price, bound to a specific request, and
 * only a `valid: boolean` ever leaves the verifier. No wallet, no amount, no
 * endpoint is revealed on-chain or to the gateway.
 */

/** Public inputs to the payment-validity proof. These are NOT secret — they are
 *  the only things the gateway and chain ever see. */
export interface PaymentPublicSignals {
  /** One-time spend tag derived from the note secret. Prevents replay/double-spend
   *  without revealing which note (or wallet) was spent. */
  nullifier: string;
  /** Poseidon Merkle root of the Pool's commitment tree the note belongs to. */
  merkleRoot: string;
  /** Field-encoded recipient (the gateway), `addressToField(account)`. Bound into
   *  the proof so a proof for one gateway can't be replayed against another. */
  payTo: string;
  /** Price tier proven to be covered, in stroops/base-units. The proof asserts
   *  note_value >= requiredAmount; the exact note value stays hidden. */
  requiredAmount: string;
  /** Poseidon hash binding the proof to THIS request (method + path + price +
   *  optional nonce), so a valid proof can't be lifted to a different endpoint. */
  contextHash: string;
}

/** A Groth16 proof bundle, as produced by snarkjs / the null-402 circuit. */
export interface ProofBundle {
  /** Groth16 proof — { pi_a, pi_b, pi_c, protocol, curve }. Opaque to the SDK. */
  proof: unknown;
  publicSignals: PaymentPublicSignals;
}

export interface VerifyResult {
  valid: boolean;
  /** Verifier reference safe to log / return in a header — no sensitive data.
   *  On-chain path: the Soroban tx/ledger ref. Dev path: a local tag. */
  proofRef: string;
  /** "soroban" = real on-chain Groth16 · "local" = real Groth16 verified off-chain
   *  with snarkjs · "dev" = insecure local scaffold. */
  mode: "soroban" | "local" | "dev";
}

/** Reason a verification was rejected (never includes private data). */
export type RejectReason =
  | "no-payment"
  | "bad-bundle"
  | "wrong-recipient"
  | "insufficient-amount"
  | "context-mismatch"
  | "unknown-root"
  | "replay"
  | "invalid-proof";

/** Stellar network configuration shared by client and server. */
export interface StellarConfig {
  /** Soroban RPC endpoint, e.g. https://soroban-testnet.stellar.org */
  rpcUrl: string;
  network: "testnet" | "mainnet" | "futurenet" | "local";
  /** Deployed null-402 Pool contract id (C...). */
  poolContractId: string;
  /** Deployed Groth16 verifier contract id (C...). */
  verifierContractId: string;
}
