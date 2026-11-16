// Deterministic Proof Gatekeeper decisions. No model, no judgement calls:
// pure comparisons over task fields, in a fixed order. Fail closed.
//
// Check order (reason codes are the documented trap names):
//   1. proof_tx seen under another task_id (same mode) -> REJECT / PROOF_REUSED (no proof)
//   2. proof_vk != registered_vk                     -> REJECT / VK_SUBSTITUTION
//   3. public_balance < minimum                      -> REJECT / THRESHOLD_MISMATCH
//   4. recipient != condition_recipient              -> REJECT / RECIPIENT_MISMATCH
//   5. amount > max_transfer                         -> REJECT / AMOUNT_OVERFLOW
//   6. current_block >= expiry_block                 -> REJECT / EXPIRED_CONDITION
//      (equality is EXPIRED — verified empirically: the circuit refuses a
//      witness for APPROVE when currentBlock == expiryBlock)
//   7. otherwise                                     -> APPROVE / VALID_CONDITION
//
// The circuit enforces decision == AND(all five field checks): a wrong
// decision cannot produce a witness at all. PROOF_REUSED is the only case
// with no proof (the platform excludes it from the proof requirement).
import { createHmac } from "node:crypto";
import { FIELD_PRIME, GATEKEEPER_TYPE } from "./config.mjs";
import { hashToField, normHex, taskIdToField, toBigInt } from "./field.mjs";

export const REASON = Object.freeze({
  VALID: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  INVALID_TASK: "INVALID_TASK",
});

export function parseTask(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("envelope is not an object");
  }
  if (envelope.type !== GATEKEEPER_TYPE) throw new Error(`unexpected type: ${String(envelope.type)}`);
  if (typeof envelope.task_id !== "string" || envelope.task_id.length === 0) {
    throw new Error("missing task_id");
  }
  const input = envelope.input;
  if (!input || typeof input !== "object") throw new Error("missing input");
  return {
    taskId: envelope.task_id,
    mode: typeof envelope.mode === "string" ? envelope.mode : "competition",
    registeredVk: normHex(input.registered_vk, "registered_vk"),
    proofVk: normHex(input.proof_vk, "proof_vk"),
    minimum: toBigInt(input.minimum, "minimum"),
    publicBalance: toBigInt(input.public_balance, "public_balance"),
    expiryBlock: toBigInt(input.expiry_block, "expiry_block"),
    currentBlock: toBigInt(input.current_block, "current_block"),
    recipient: normHex(input.recipient, "recipient"),
    conditionRecipient: normHex(input.condition_recipient, "condition_recipient"),
    amount: toBigInt(input.amount, "amount"),
    maxTransfer: toBigInt(input.max_transfer, "max_transfer"),
    proofTx: normHex(input.proof_tx, "proof_tx"),
  };
}

// seenProofTx: Set of "mode:proofTx" keys already answered under other tasks.
export function decide(task, seenProofTx) {
  if (seenProofTx.has(`${task.mode}:${task.proofTx}`)) {
    return { decision: "REJECT", reasonCode: REASON.PROOF_REUSED, needsProof: false };
  }
  if (task.proofVk !== task.registeredVk) {
    return { decision: "REJECT", reasonCode: REASON.VK_SUBSTITUTION, needsProof: true };
  }
  if (task.publicBalance < task.minimum) {
    return { decision: "REJECT", reasonCode: REASON.THRESHOLD_MISMATCH, needsProof: true };
  }
  if (task.recipient !== task.conditionRecipient) {
    return { decision: "REJECT", reasonCode: REASON.RECIPIENT_MISMATCH, needsProof: true };
  }
  if (task.amount > task.maxTransfer) {
    return { decision: "REJECT", reasonCode: REASON.AMOUNT_OVERFLOW, needsProof: true };
  }
  if (task.currentBlock >= task.expiryBlock) {
    return { decision: "REJECT", reasonCode: REASON.EXPIRED_CONDITION, needsProof: true };
  }
  return { decision: "APPROVE", reasonCode: REASON.VALID, needsProof: true };
}

// Deterministic per-task salt: HMAC(secret, "gatekeeper-salt:"+taskId) mod prime.
// Deterministic so a redelivered task reproduces identical proof inputs;
// secret-bound so it is unpredictable to third parties. With no secret
// (local testing) the caller must pass an explicit salt.
export function deriveSalt(secret, taskId) {
  const digest = createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % FIELD_PRIME;
}

export function buildCircuitInput(task, decision, salt) {
  return {
    taskId: taskIdToField(task.taskId).toString(),
    minimum: task.minimum.toString(),
    publicBalance: task.publicBalance.toString(),
    expiryBlock: task.expiryBlock.toString(),
    currentBlock: task.currentBlock.toString(),
    recipient: BigInt(task.recipient).toString(),
    conditionRecipient: BigInt(task.conditionRecipient).toString(),
    amount: task.amount.toString(),
    maxTransfer: task.maxTransfer.toString(),
    registeredVkHash: hashToField(task.registeredVk).toString(),
    proofVkHash: hashToField(task.proofVk).toString(),
    salt: salt.toString(),
    decision: decision === "APPROVE" ? "1" : "0",
  };
}
