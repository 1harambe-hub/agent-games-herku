// Empirical gatekeeper circuit tests — verifies spec facts against the real wasm/zkey.
// Spec facts under test (from independent participant reports + official docs):
// signals: taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
// conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash, salt, decision.
// Public signals: [commitment=Poseidon(salt,taskId), registeredVkHash, proofVkHash,
// minimum, publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
// amount, maxTransfer, decision, taskId]
import { groth16 } from "snarkjs";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { buildPoseidon } from "circomlibjs";

const PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x13aa0000000000000000000000000000000000000000000000000000000000ff";
const RECIP = "0xde42000000000000000000000000000000009f01";

const vk = JSON.parse(readFileSync("circuits/gatekeeper_vk.json", "utf8"));
const poseidon = await buildPoseidon();

function taskIdField(s) {
  return BigInt("0x" + Buffer.from(s, "utf8").toString("hex"));
}
function hashField(hex) {
  return BigInt(hex) % PRIME;
}

function buildInput(t, decision, salt) {
  return {
    taskId: taskIdField(t.taskId).toString(),
    minimum: String(t.minimum),
    publicBalance: String(t.publicBalance),
    expiryBlock: String(t.expiryBlock),
    currentBlock: String(t.currentBlock),
    recipient: BigInt(t.recipient).toString(),
    conditionRecipient: BigInt(t.conditionRecipient).toString(),
    amount: String(t.amount),
    maxTransfer: String(t.maxTransfer),
    registeredVkHash: hashField(t.registeredVk).toString(),
    proofVkHash: hashField(t.proofVk).toString(),
    salt: salt.toString(),
    decision: String(decision),
  };
}

const base = {
  taskId: "gk_24_9d1",
  minimum: 1000, publicBalance: 1460,
  expiryBlock: 8430000, currentBlock: 8420000,
  recipient: RECIP, conditionRecipient: RECIP,
  amount: 500, maxTransfer: 1000,
  registeredVk: VK_HASH, proofVk: VK_HASH,
};

console.log("VK_HASH exceeds prime?", BigInt(VK_HASH) >= PRIME);
console.log("VK_HASH mod prime:", hashField(VK_HASH).toString().slice(0, 40) + "...");

async function tryProve(name, task, decision) {
  const salt = BigInt("0x" + randomBytes(16).toString("hex"));
  const input = buildInput(task, decision, salt);
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await groth16.fullProve(input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
    const ok = await groth16.verify(vk, publicSignals, proof);
    console.log(`[${name}] PROVED in ${Date.now() - t0}ms, verify=${ok}, nPublic=${publicSignals.length}`);
    return { proof, publicSignals, salt, input };
  } catch (e) {
    console.log(`[${name}] WITNESS/PROVE FAILED: ${String(e.message || e).slice(0, 160)}`);
    return null;
  }
}

// 1. Valid + APPROVE
const r1 = await tryProve("valid+APPROVE", base, 1);
if (r1) {
  const ps = r1.publicSignals;
  const expectedCommit = poseidon.F.toObject(poseidon([r1.salt, taskIdField(base.taskId)])).toString();
  console.log("  commitment==Poseidon(salt,taskId)?", ps[0] === expectedCommit);
  console.log("  ps[1]==registeredVkHash?", ps[1] === hashField(VK_HASH).toString());
  console.log("  ps[2]==proofVkHash?", ps[2] === hashField(VK_HASH).toString());
  console.log("  ps[3..6]:", ps[3], ps[4], ps[5], ps[6], "(expect 1000 1460 8430000 8420000)");
  console.log("  ps[7]==recipient?", ps[7] === BigInt(RECIP).toString());
  console.log("  ps[9..10]:", ps[9], ps[10], "(expect 500 1000)");
  console.log("  ps[11]==decision?", ps[11], "(expect 1)");
  console.log("  ps[12]==taskId?", ps[12] === taskIdField(base.taskId).toString());
}

// 2. Trap (VK mismatch) + REJECT
await tryProve("vkTrap+REJECT", { ...base, proofVk: OTHER_VK }, 0);
// 3. Trap + APPROVE (must fail)
await tryProve("vkTrap+APPROVE", { ...base, proofVk: OTHER_VK }, 1);
// 4. Valid + REJECT (must fail per 'decision==AND(checks)')
await tryProve("valid+REJECT", base, 0);
// 5. Boundary: currentBlock == expiryBlock + APPROVE
await tryProve("expiryEqual+APPROVE", { ...base, currentBlock: 8430000 }, 1);
// 5b. Boundary: currentBlock == expiryBlock + REJECT
await tryProve("expiryEqual+REJECT", { ...base, currentBlock: 8430000 }, 0);
// 6. Boundary: balance == minimum + APPROVE
await tryProve("balanceEqual+APPROVE", { ...base, publicBalance: 1000 }, 1);
// 7. Boundary: amount == maxTransfer + APPROVE
await tryProve("amountEqual+APPROVE", { ...base, amount: 1000 }, 1);
// 8. Threshold trap + REJECT
await tryProve("thresholdTrap+REJECT", { ...base, publicBalance: 999 }, 0);
process.exit(0);
