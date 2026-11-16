// Steal the VFY turn handling. The policy is enforced by the vfy-policy
// circuit: the proof only exists when the action matches the committed
// strategy params, so the decision logic below MUST mirror the circuit.
//
// Circuit policy (verified empirically):
//   selfBalance < params[1]      -> FORTIFY
//   opponentBalance < params[2]  -> HOLD
//   otherwise                    -> EXTRACT params[0]
// Commitment = Poseidon(params[0..7], salt); registered on the dashboard as
// 0x + 64 hex chars. The SAME params+salt must back the running agent.
//
// Turn envelope (from /build): protocolVersion, eventId "steal-the-vfy",
// mode, matchId, turn, issuedAt, deadlineAt, state {selfBalance,
// opponentBalance, selfFortifiedUntilTurn, opponentFortifiedUntilTurn},
// strategyCommitment {hash}, resolverVersion, nonce.
//
// Response: {matchId, turn, action: {type, amount?}, policyProof:
// {circuitVersion: "v1", proof, public_signals, publicInputsHash?},
// agentTimestamp, idempotencyKey}. amount MUST be omitted for HOLD/FORTIFY.
import { randomUUID } from "node:crypto";
import { buildPoseidon } from "circomlibjs";
import { keccak_256 } from "js-sha3";
import { matchIdToField, toBigInt } from "./field.mjs";
import { STEAL_EVENT_ID } from "./config.mjs";

export const ACTION_CODE = Object.freeze({ HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n });

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

export async function computeCommitment(params, salt) {
  const poseidon = await getPoseidon();
  const hash = poseidon.F.toObject(poseidon([...params, salt]));
  return {
    decimal: hash.toString(),
    hex: "0x" + hash.toString(16).padStart(64, "0"),
  };
}

export function parseTurn(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("envelope is not an object");
  }
  if (envelope.eventId !== STEAL_EVENT_ID) throw new Error(`unexpected eventId: ${String(envelope.eventId)}`);
  if (typeof envelope.matchId !== "string" || envelope.matchId.length === 0) {
    throw new Error("missing matchId");
  }
  const turn = toBigInt(envelope.turn, "turn");
  const state = envelope.state;
  if (!state || typeof state !== "object") throw new Error("missing state");
  return {
    matchId: envelope.matchId,
    turn,
    mode: typeof envelope.mode === "string" ? envelope.mode : "competition",
    selfBalance: toBigInt(state.selfBalance, "selfBalance"),
    opponentBalance: toBigInt(state.opponentBalance, "opponentBalance"),
    commitmentHash: envelope.strategyCommitment?.hash ?? null,
  };
}

// Mirror of the circuit policy. Returns {type, amountNum}.
export function decideMove(turn, params) {
  if (turn.selfBalance < params[1]) return { type: "FORTIFY", amountNum: 0 };
  if (turn.opponentBalance < params[2]) return { type: "HOLD", amountNum: 0 };
  const amount = Number(params[0]);
  if (!Number.isSafeInteger(amount) || amount < 1 || amount > 10) {
    throw new Error(`extract amount out of range: ${amount}`);
  }
  return { type: "EXTRACT", amountNum: amount };
}

export function buildCircuitInput(turn, move, params, salt, commitmentDecimal) {
  return {
    commitment: commitmentDecimal,
    matchId: matchIdToField(turn.matchId).toString(),
    turnNumber: turn.turn.toString(),
    selfBalance: turn.selfBalance.toString(),
    opponentBalance: turn.opponentBalance.toString(),
    action: ACTION_CODE[move.type].toString(),
    amount: String(move.amountNum),
    circuitVersion: "1",
    salt: salt.toString(),
    strategyParams: params.map((p) => p.toString()),
  };
}

// Optional audit pointer: keccak256 of the 8 ABI-packed 32-byte fields.
// (The platform verifies the Groth16 proof itself; this hash is not used
// for verification, but the /build guide documents the exact formula.)
export function computePublicInputsHash(turn, move, commitmentDecimal) {
  const fields = [
    BigInt(commitmentDecimal),
    matchIdToField(turn.matchId),
    turn.turn,
    turn.selfBalance,
    turn.opponentBalance,
    ACTION_CODE[move.type],
    BigInt(move.amountNum),
    1n,
  ];
  const packed = Buffer.concat(
    fields.map((f) => {
      const hex = f.toString(16).padStart(64, "0");
      return Buffer.from(hex, "hex");
    }),
  );
  return "0x" + keccak_256(packed);
}

export function buildResponse(turn, move, proof, publicSignals, publicInputsHash) {
  const action = move.type === "EXTRACT"
    ? { type: "EXTRACT", amount: move.amountNum }
    : { type: move.type };
  return {
    matchId: turn.matchId,
    turn: Number(turn.turn),
    action,
    policyProof: {
      circuitVersion: "v1",
      proof,
      public_signals: publicSignals,
      publicInputsHash,
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: randomUUID(),
  };
}
