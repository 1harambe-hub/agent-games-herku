// Shared configuration. All secrets come from environment variables only.
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DIR = dirname(fileURLToPath(import.meta.url));
export const CIRCUIT_DIR = process.env.CIRCUIT_DIR || join(DIR, "circuits");

export const PORT = Number(process.env.PORT || 3000);
export const STATE_FILE = process.env.STATE_FILE || join(DIR, "state.json");
export const PROTOCOL_VERSION = "v1";

export const PREFLIGHT_TYPE = "agent-games.preflight.v1";
export const GATEKEEPER_TYPE = "agent-games.proof-gatekeeper.v1";
export const STEAL_EVENT_ID = "steal-the-vfy";

export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
export const VFY_POLICY_VK_HASH =
  "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";

// BN128 scalar field prime (snarkjs/circom BN128).
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Proof generation budget per task; the platform deadline is 60s (gatekeeper)
// and ~30s per push (steal). On budget expiry we answer the decision WITHOUT
// a proof rather than timing out.
export const PROOF_TIMEOUT_MS = Number(process.env.PROOF_TIMEOUT_MS || 40000);

export function hmacSecret() {
  return process.env.AGENT_GAMES_HMAC_SECRET || "";
}

export function circuitsPresent() {
  const need = [
    "gatekeeper.wasm",
    "gatekeeper_final.zkey",
    "gatekeeper_vk.json",
    "vfy-policy.wasm",
    "vfy-policy_final.zkey",
    "vfy-policy_vk.json",
  ];
  const out = {};
  for (const f of need) out[f] = existsSync(join(CIRCUIT_DIR, f));
  return out;
}

// Steal-the-VFY strategy. EIGHT params + salt; the commitment registered on
// the dashboard MUST be Poseidon(params[0..7], salt) or every turn fails.
// Policy enforced by the circuit: selfBalance < params[1] -> FORTIFY;
// opponentBalance < params[2] -> HOLD; otherwise EXTRACT params[0].
// Defaults: extract 10, fortify when own balance < 20, never hold.
export function stealConfig() {
  const raw = process.env.STEAL_VFY_PARAMS || "10,20,0,0,0,0,0,0";
  const params = raw.split(",").map((x) => BigInt(x.trim()));
  if (params.length !== 8) throw new Error("STEAL_VFY_PARAMS must be 8 comma-separated integers");
  const saltRaw = process.env.STEAL_VFY_SALT || "";
  const salt = saltRaw === "" ? null : BigInt(saltRaw.trim());
  return { params, salt };
}
