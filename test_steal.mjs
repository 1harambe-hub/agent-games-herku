// Empirical vfy-policy circuit tests — verifies spec facts against the real wasm/zkey.
// Claimed inputs (from a public dual-track implementation + /build guide):
// commitment, matchId, turnNumber, selfBalance, opponentBalance, action,
// amount, circuitVersion (public), salt + strategyParams[8] (private).
// Commitment = Poseidon(params[0..7], salt). Policy: selfBalance < params[1]
// -> FORTIFY; opponentBalance < params[2] -> HOLD; else EXTRACT params[0].
import { groth16 } from "snarkjs";
import { readFileSync } from "node:fs";
import { buildPoseidon } from "circomlibjs";

const vk = JSON.parse(readFileSync("circuits/vfy-policy_vk.json", "utf8"));
const poseidon = await buildPoseidon();

const PARAMS = [8n, 18n, 8n, 0n, 0n, 0n, 0n, 0n];
const SALT = 12345678901234567890n;
const commitment = poseidon.F.toObject(poseidon([...PARAMS, SALT]));
console.log("commitment:", commitment.toString().slice(0, 40) + "...");

function matchIdField(id) {
  return BigInt("0x" + String(id).replace(/-/g, ""));
}

function buildInput({ matchId, turn, selfBalance, opponentBalance, action, amount }) {
  return {
    commitment: commitment.toString(),
    matchId: matchIdField(matchId).toString(),
    turnNumber: String(turn),
    selfBalance: String(selfBalance),
    opponentBalance: String(opponentBalance),
    action: String(action),
    amount: String(amount),
    circuitVersion: "1",
    salt: SALT.toString(),
    strategyParams: PARAMS.map(String),
  };
}

async function tryProve(name, args) {
  const input = buildInput(args);
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await groth16.fullProve(input, "circuits/vfy-policy.wasm", "circuits/vfy-policy_final.zkey");
    const ok = await groth16.verify(vk, publicSignals, proof);
    console.log(`[${name}] PROVED in ${Date.now() - t0}ms, verify=${ok}, nPublic=${publicSignals.length}`);
    return publicSignals;
  } catch (e) {
    console.log(`[${name}] WITNESS/PROVE FAILED: ${String(e.message || e).slice(0, 160)}`);
    return null;
  }
}

const MID = "9f4e1b2a-0000-4000-8000-000000000001";
// 1. EXTRACT 8 (both healthy)
const ps = await tryProve("extract8", { matchId: MID, turn: 3, selfBalance: 100, opponentBalance: 100, action: 2, amount: 8 });
if (ps) {
  console.log("  ps:", ps.map((s) => String(s).slice(0, 24)).join(" | "));
  console.log("  ps[1]==commitment?", ps[1] === commitment.toString());
  console.log("  ps[2]==matchId?", ps[2] === matchIdField(MID).toString());
  console.log("  ps[3..8]:", ps.slice(3).join(" "), "(expect 3 100 100 2 8 1)");
  // what is ps[0]? try Poseidon of the 8 public inputs? print only
  console.log("  ps[0] (output):", ps[0].slice(0, 40) + "...");
}
// 2. Wrong action: HOLD when policy says EXTRACT -> must fail
await tryProve("wrongHold", { matchId: MID, turn: 3, selfBalance: 100, opponentBalance: 100, action: 0, amount: 0 });
// 3. FORTIFY when selfBalance < 18
await tryProve("fortify", { matchId: MID, turn: 4, selfBalance: 10, opponentBalance: 100, action: 1, amount: 0 });
// 4. HOLD when opponentBalance < 8
await tryProve("hold", { matchId: MID, turn: 5, selfBalance: 100, opponentBalance: 5, action: 0, amount: 0 });
// 5. Wrong amount: EXTRACT 5 when policy says 8 -> must fail
await tryProve("wrongAmount", { matchId: MID, turn: 3, selfBalance: 100, opponentBalance: 100, action: 2, amount: 5 });
// 6. FORTIFY when healthy -> must fail
await tryProve("wrongFortify", { matchId: MID, turn: 3, selfBalance: 100, opponentBalance: 100, action: 1, amount: 0 });
process.exit(0);
