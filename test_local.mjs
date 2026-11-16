// Local end-to-end harness: boots the server on a test port and replays
// platform-style envelopes (HMAC-signed, preflight, all 7 trap types,
// idempotent redelivery, bad signature, steal turns). Verifies response
// signatures and re-verifies every returned proof against the local VKs.
// Run: node test_local.mjs  (uses a scratch STATE_FILE; no network needed)
import { spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { groth16 } from "snarkjs";
import { readFileSync } from "node:fs";

const SECRET = "test-secret-" + randomBytes(8).toString("hex");
const PORT = 3456;
const BASE = `http://127.0.0.1:${PORT}`;
const SALT = "98765432109876543210";
const PARAMS = "10,20,0,0,0,0,0,0";

const gkVk = JSON.parse(readFileSync("circuits/gatekeeper_vk.json", "utf8"));
const vfVk = JSON.parse(readFileSync("circuits/vfy-policy_vk.json", "utf8"));

let pass = 0, fail = 0;
function check(name, cond, extra = "") {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
}

function sign(body) {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}
function verifyRespSig(bodyText, sig) {
  if (!sig) return false;
  return sign(bodyText) === sig.trim().toLowerCase();
}

async function post(path, envelope, sigOverride) {
  const body = JSON.stringify(envelope);
  const sig = sigOverride === undefined ? sign(body) : sigOverride;
  const r = await fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...(sig ? { "x-agent-games-signature": sig } : {}) },
    body,
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep null */ }
  return { status: r.status, text, json, sig: r.headers.get("x-agent-games-signature") };
}

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK2 = "0x13aa0000000000000000000000000000000000000000000000000000000000ff";
const RECIP = "0xde42000000000000000000000000000000009f01";
const RECIP2 = "0xbeef00000000000000000000000000000000000001";

function gkTask(taskId, overrides = {}, proofTx) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIP,
      condition_recipient: RECIP,
      amount: "500",
      max_transfer: "1000",
      proof_tx: proofTx || ("0x" + randomBytes(32).toString("hex")),
      ...overrides,
    },
  };
}

async function main() {
  const child = spawn("node", ["server.mjs"], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      STEAL_VFY_PARAMS: PARAMS,
      STEAL_VFY_SALT: SALT,
      STATE_FILE: "/tmp/zkv-agent-test-state.json",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  child.stdout.on("data", (d) => { serverLog += d; });
  child.stderr.on("data", (d) => { serverLog += d; });
  try {
    // wait for readiness
    for (let i = 0; i < 40; i++) {
      try {
        const r = await fetch(BASE + "/health");
        if (r.ok) break;
      } catch { /* not up yet */ }
      await new Promise((r) => setTimeout(r, 500));
    }
    const health = await (await fetch(BASE + "/health")).json();
    console.log("== health ==");
    check("health ok", health.ok === true, JSON.stringify(health.selfTest));

    console.log("== preflight ==");
    const pf = await post("/agent", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
    check("preflight 200", pf.status === 200);
    check("preflight body", pf.json?.ok === true && pf.json?.protocolVersion === "v1");
    check("preflight signed", verifyRespSig(pf.text, pf.sig));

    console.log("== bad signature ==");
    const bad = await post("/agent", gkTask("gk_bad"), "0".repeat(64));
    check("bad sig -> 401", bad.status === 401);
    const nosig = await post("/agent", gkTask("gk_nosig"), null);
    check("no sig -> 401", nosig.status === 401);

    console.log("== gatekeeper decisions + proofs ==");
    const cases = [
      ["valid", gkTask("gk_valid"), "APPROVE", "VALID_CONDITION", true],
      ["vkTrap", gkTask("gk_vk", { proof_vk: VK2 }), "REJECT", "VK_SUBSTITUTION", true],
      ["threshold", gkTask("gk_thr", { public_balance: "999" }), "REJECT", "THRESHOLD_MISMATCH", true],
      ["recipient", gkTask("gk_rec", { recipient: RECIP2 }), "REJECT", "RECIPIENT_MISMATCH", true],
      ["overflow", gkTask("gk_amt", { amount: "1001" }), "REJECT", "AMOUNT_OVERFLOW", true],
      ["expired", gkTask("gk_exp", { current_block: 8430000 }), "REJECT", "EXPIRED_CONDITION", true],
      ["expiredPast", gkTask("gk_exp2", { current_block: 8430001 }), "REJECT", "EXPIRED_CONDITION", true],
      ["boundaryBalance", gkTask("gk_beq", { public_balance: "1000" }), "APPROVE", "VALID_CONDITION", true],
      ["boundaryAmount", gkTask("gk_aeq", { amount: "1000" }), "APPROVE", "VALID_CONDITION", true],
    ];
    for (const [name, env, decision, reason, withProof] of cases) {
      const r = await post("/agent", env);
      check(`${name} 200`, r.status === 200);
      check(`${name} decision`, r.json?.decision === decision && r.json?.reason_code === reason,
        `got ${r.json?.decision}/${r.json?.reason_code}`);
      check(`${name} signed`, verifyRespSig(r.text, r.sig));
      if (withProof) {
        const okProof = r.json?.proof && r.json?.public_signals?.length === 13 &&
          (await groth16.verify(gkVk, r.json.public_signals, r.json.proof));
        check(`${name} proof verifies`, okProof === true);
      }
    }

    console.log("== proof reuse + idempotency ==");
    const sharedTx = "0x" + randomBytes(32).toString("hex");
    const first = await post("/agent", gkTask("gk_reuse1", {}, sharedTx));
    check("first use APPROVE", first.json?.decision === "APPROVE");
    const second = await post("/agent", gkTask("gk_reuse2", {}, sharedTx));
    check("second use PROOF_REUSED", second.json?.decision === "REJECT" && second.json?.reason_code === "PROOF_REUSED");
    check("reused has no proof", !second.json?.proof);
    const r1 = await post("/agent", gkTask("gk_idem"));
    const r2 = await post("/agent", gkTask("gk_idem"));
    check("same task_id -> identical body", r1.text === r2.text);
    check("replay still signed", verifyRespSig(r2.text, r2.sig));

    console.log("== steal the vfy ==");
    function stealTurn(matchId, turn, selfB, oppB) {
      return {
        protocolVersion: "v1",
        eventId: "steal-the-vfy",
        mode: "competition",
        matchId,
        turn,
        issuedAt: new Date().toISOString(),
        deadlineAt: new Date(Date.now() + 300000).toISOString(),
        state: { selfBalance: String(selfB), opponentBalance: String(oppB), selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
        strategyCommitment: { hash: "0x0" },
        resolverVersion: "v1",
        nonce: "n" + turn,
      };
    }
    const MID = "9f4e1b2a-1111-4000-8000-000000000001";
    const t1 = await post("/agent", stealTurn(MID, 1, 100, 100));
    check("steal extract 200", t1.status === 200, t1.text.slice(0, 120));
    check("steal extract action", t1.json?.action?.type === "EXTRACT" && t1.json?.action?.amount === 10, JSON.stringify(t1.json?.action));
    check("steal signed", verifyRespSig(t1.text, t1.sig));
    check("steal proof verifies", t1.json?.policyProof?.public_signals?.length === 9 &&
      (await groth16.verify(vfVk, t1.json.policyProof.public_signals, t1.json.policyProof.proof)) === true);
    check("steal publicInputsHash present", typeof t1.json?.policyProof?.publicInputsHash === "string" && t1.json.policyProof.publicInputsHash.startsWith("0x"));
    const t2 = await post("/agent", stealTurn(MID, 2, 10, 100));
    check("steal fortify", t2.json?.action?.type === "FORTIFY" && !("amount" in (t2.json?.action || {})), JSON.stringify(t2.json?.action));
    check("steal fortify proof verifies", t2.json?.policyProof?.public_signals?.length === 9 &&
      (await groth16.verify(vfVk, t2.json.policyProof.public_signals, t2.json.policyProof.proof)) === true);
    const t3 = await post("/agent", stealTurn(MID, 3, 100, 5));
    // opponentBalance 5 < params[2]=0? No: 5 < 0 is false -> EXTRACT. params[2]=0 disables HOLD.
    check("steal low-opp extracts", t3.json?.action?.type === "EXTRACT", JSON.stringify(t3.json?.action));
    const t1replay = await post("/agent", stealTurn(MID, 1, 100, 100));
    check("steal idempotent replay", t1replay.text === t1.text);
  } finally {
    child.kill("SIGTERM");
  }
  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error("HARNESS ERROR", e); process.exit(2); });
