/**
 * snarkjs ⇄ Soroban byte encoding for BN254 points / field elements.
 *
 * Uncompressed affine, 32-byte big-endian field elements:
 *   field (32B)
 *   G1    (64B)  = x ‖ y
 *   G2    (128B) = x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0   (EIP-197 / BN254 "imaginary first")
 *
 * This matches the verifier contract's `Bn254*::from_bytes` layout and the
 * null-402-circuits converter — confirmed by the on-chain verify returning true.
 */

/** Decimal field-element string → 32-byte big-endian. */
export function fieldToBytes(dec: string): Uint8Array {
  let n = BigInt(dec);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/** snarkjs G1 point [x, y, z] (z=1, affine) → 64 bytes. */
export function g1ToBytes(p: string[]): Uint8Array {
  const [x, y] = p as [string, string];
  const out = new Uint8Array(64);
  out.set(fieldToBytes(x), 0);
  out.set(fieldToBytes(y), 32);
  return out;
}

/** snarkjs G2 point [[x.c0,x.c1],[y.c0,y.c1],...] → 128 bytes (imaginary first). */
export function g2ToBytes(p: string[][]): Uint8Array {
  const [x, y] = p as [[string, string], [string, string]];
  const out = new Uint8Array(128);
  out.set(fieldToBytes(x[1]), 0); // x.c1
  out.set(fieldToBytes(x[0]), 32); // x.c0
  out.set(fieldToBytes(y[1]), 64); // y.c1
  out.set(fieldToBytes(y[0]), 96); // y.c0
  return out;
}
