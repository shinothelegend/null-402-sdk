/**
 * Proof transport + request binding.
 *
 * The X-PAYMENT header carries a base64url(JSON) ProofBundle. The contextHash
 * binds a proof to one specific request so it can't be replayed elsewhere.
 */

import type { ProofBundle, PaymentPublicSignals } from "./types.js";

const enc = new TextEncoder();

/** Encode a proof bundle for the `X-PAYMENT` header. */
export function encodePayment(bundle: ProofBundle): string {
  const json = JSON.stringify(bundle);
  return base64urlFromBytes(enc.encode(json));
}

/** Decode an `X-PAYMENT` header value back into a proof bundle. Returns null on
 *  any malformed input — never throws into request handling. */
export function decodePayment(header: string | null | undefined): ProofBundle | null {
  if (!header || header.trim() === "") return null;
  try {
    const bytes = bytesFromBase64url(header.trim());
    const obj = JSON.parse(new TextDecoder().decode(bytes)) as ProofBundle;
    if (!obj || typeof obj !== "object" || !obj.publicSignals) return null;
    const s = obj.publicSignals as Partial<PaymentPublicSignals>;
    if (!s.nullifier || !s.merkleRoot || !s.payTo || !s.requiredAmount || !s.contextHash) {
      return null;
    }
    return obj;
  } catch {
    return null;
  }
}

/**
 * Canonical request fingerprint that both client and circuit hash into
 * `contextHash`. Keep this deterministic and stable across SDK versions.
 *
 * NOTE: The on-chain proof must hash these same fields with Poseidon inside the
 * circuit. This helper produces the *preimage*; `hashContext` produces the
 * field element. See packages/circuits for the matching circuit constraint.
 */
export function contextPreimage(input: {
  method: string;
  path: string;
  requiredAmount: string | number;
  payTo: string;
  nonce?: string;
}): string {
  return [
    input.method.toUpperCase(),
    input.path,
    String(input.requiredAmount),
    input.payTo,
    input.nonce ?? "",
  ].join("\n");
}

/** BN254 scalar field modulus (Fr) — every circuit signal lives in this field. */
export const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Reduce an arbitrary string to a BN254 field element (decimal string) via
 *  SHA-256. Maps non-field values (addresses, request preimages) into the field
 *  the circuit operates over. */
export async function toField(input: string): Promise<string> {
  const digest = await sha256(enc.encode(input));
  let n = 0n;
  for (const b of digest) n = (n << 8n) | BigInt(b);
  return (n % BN254_FR).toString();
}

/** Field-encode a Stellar account/contract id for the proof's `payTo` signal. */
export async function addressToField(address: string): Promise<string> {
  return toField("null402:payTo:" + address);
}

/**
 * Bind a request to a field element (the circuit's `contextHash` public input).
 * Client (proving) and gateway (checking) call this on the same canonical
 * preimage, so a valid proof can't be lifted to a different request.
 */
export async function hashContext(preimage: string): Promise<string> {
  return toField(preimage);
}

// ── encoding helpers (runtime-agnostic: Workers, Node, browser) ───────────────

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  // Copy into a fresh ArrayBuffer-backed view so the WebCrypto BufferSource type
  // is satisfied without depending on TS's (version-specific) typed-array generics.
  const data = new Uint8Array(bytes.byteLength);
  data.set(bytes);
  const buf = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return new Uint8Array(buf);
}

function base64urlFromBytes(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesFromBase64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
