// Local Groth16 proving with snarkjs + the official circuits. No network,
// no keys, no spending: proofs are generated locally and returned to the
// platform, which re-verifies them against its own verification keys.
import { groth16 } from "snarkjs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CIRCUIT_DIR, PROOF_TIMEOUT_MS } from "./config.mjs";

const vkCache = {};

export function loadVk(kind) {
  if (!vkCache[kind]) {
    const file = kind === "gatekeeper" ? "gatekeeper_vk.json" : "vfy-policy_vk.json";
    vkCache[kind] = JSON.parse(readFileSync(join(CIRCUIT_DIR, file), "utf8"));
  }
  return vkCache[kind];
}

function artifactPaths(kind) {
  if (kind === "gatekeeper") {
    return { wasm: join(CIRCUIT_DIR, "gatekeeper.wasm"), zkey: join(CIRCUIT_DIR, "gatekeeper_final.zkey") };
  }
  return { wasm: join(CIRCUIT_DIR, "vfy-policy.wasm"), zkey: join(CIRCUIT_DIR, "vfy-policy_final.zkey") };
}

// Rejects on timeout or on circuit assertion failure (wrong decision).
export async function generateProof(kind, circuitInput, timeoutMs = PROOF_TIMEOUT_MS) {
  const { wasm, zkey } = artifactPaths(kind);
  const t0 = Date.now();
  const work = groth16.fullProve(circuitInput, wasm, zkey);
  const timer = new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`proof generation exceeded ${timeoutMs}ms`)), timeoutMs),
  );
  const { proof, publicSignals } = await Promise.race([work, timer]);
  return { proof, publicSignals, proofMs: Date.now() - t0 };
}

export async function verifyProof(kind, proof, publicSignals) {
  return groth16.verify(loadVk(kind), publicSignals, proof);
}
