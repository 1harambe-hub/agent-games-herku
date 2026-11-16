// Field-element encodings for circuit inputs. Verified empirically against
// the official circuits (see test_gatekeeper.mjs / test_steal.mjs).
import { FIELD_PRIME } from "./config.mjs";

const HEX_RE = /^0x[0-9a-fA-F]+$/;

export function isHex(value) {
  return typeof value === "string" && HEX_RE.test(value.trim());
}

export function normHex(value, field) {
  if (!isHex(value)) throw new Error(`bad hex for ${field}`);
  return value.trim().toLowerCase();
}

// Accept numbers, decimal strings, or 0x hex strings; return BigInt.
export function toBigInt(value, field) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`bad number for ${field}`);
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (HEX_RE.test(s)) return BigInt(s);
    if (/^\d+$/.test(s)) return BigInt(s);
    throw new Error(`bad numeric string for ${field}: ${s.slice(0, 40)}`);
  }
  throw new Error(`bad type for ${field}: ${typeof value}`);
}

// 256-bit hashes exceed the BN128 scalar field: the circuit sees the value
// reduced mod the field prime (verified: the registered vk hash itself is
// larger than the prime, and reduced values verify).
export function hashToField(hex) {
  return BigInt(hex) % FIELD_PRIME;
}

// Task IDs are strings ("gk_24_9d1"). Encoding: BigInt of the UTF-8 bytes.
// This encoding produced platform-VERIFIED proofs in live practice mode for
// an independent participant (Nov 2026); it is the best-known encoding.
export function taskIdToField(taskId) {
  return BigInt("0x" + Buffer.from(taskId, "utf8").toString("hex"));
}

// UUID-style match IDs: strip dashes, parse as hex (128-bit, fits the field).
export function matchIdToField(matchId) {
  const hex = String(matchId).replace(/^0x/i, "").replace(/-/g, "");
  if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error("bad matchId");
  return BigInt("0x" + hex);
}
