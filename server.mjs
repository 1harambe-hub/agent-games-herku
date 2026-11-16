// Agent Games arena endpoint — plain Node.js http, no framework.
//
//   POST /agent  (primary; /gatekeeper accepted as an alias)
//     - Verifies x-agent-games-signature over the RAW body BEFORE parsing.
//       Mismatch -> 401, no processing.
//     - type "agent-games.preflight.v1" -> signed { ok: true, protocolVersion: "v1" }.
//     - type "agent-games.proof-gatekeeper.v1" -> deterministic decision +
//       local Groth16 proof, signed. Proof budget PROOF_TIMEOUT_MS; on expiry
//       the decision is answered WITHOUT a proof rather than timing out.
//     - eventId "steal-the-vfy" -> policy move + policy proof, signed.
//     - Every response carries x-agent-games-signature over the raw body.
//   GET /health -> readiness JSON (no secrets). GET on /agent also returns
//     200 status JSON in case the platform probes the endpoint with GET.
//
// This server NEVER signs transactions, NEVER spends anything, and NEVER
// holds a private key or seed. The only secret is the platform HMAC secret
// from AGENT_GAMES_HMAC_SECRET (never logged).
import http from "node:http";
import {
  CIRCUIT_DIR,
  GATEKEEPER_TYPE,
  GATEKEEPER_VK_HASH,
  PORT,
  PREFLIGHT_TYPE,
  PROTOCOL_VERSION,
  STEAL_EVENT_ID,
  circuitsPresent,
  hmacSecret,
  stealConfig,
} from "./config.mjs";
import { hmacHex, verifySignature } from "./hmac.mjs";
import { REASON, buildCircuitInput, decide, deriveSalt, parseTask } from "./gatekeeper.mjs";
import {
  buildCircuitInput as buildStealInput,
  buildResponse as buildStealResponse,
  computeCommitment,
  computePublicInputsHash,
  decideMove,
  parseTurn,
} from "./steal.mjs";
import { generateProof, loadVk, verifyProof } from "./prover.mjs";
import { StateStore } from "./state.mjs";

const state = new StateStore();
const selfTest = { ranAt: null, ok: null, detail: null };

function sendJson(res, status, bodyObj, secret) {
  const body = JSON.stringify(bodyObj);
  const headers = { "content-type": "application/json" };
  if (secret) headers["x-agent-games-signature"] = hmacHex(secret, body);
  res.writeHead(status, headers);
  res.end(body);
}

function sendCached(res, body, secret) {
  res.writeHead(200, {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(secret, body),
  });
  res.end(body);
}

function readRawBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let failed = false;
    req.on("data", (c) => {
      if (failed) return;
      size += c.length;
      if (size > limit) { failed = true; reject(new Error("body too large")); }
      else chunks.push(c);
    });
    req.on("end", () => { if (!failed) resolve(Buffer.concat(chunks)); });
    req.on("error", reject);
  });
}

async function handleGatekeeperTask(envelope, secret) {
  let task;
  try {
    task = parseTask(envelope);
  } catch (e) {
    console.warn(`[gatekeeper] invalid task: ${e.message}`);
    return { status: 200, body: { decision: "REJECT", reason_code: REASON.INVALID_TASK } };
  }

  const cacheKey = `gk:${task.taskId}`;
  const cached = state.getCached(cacheKey);
  if (cached) return { status: 200, cachedBody: cached };

  const { decision, reasonCode, needsProof } = decide(task, state.seen);
  const response = { decision, reason_code: reasonCode, proof_tx: task.proofTx };

  if (needsProof) {
    try {
      const salt = deriveSalt(secret, task.taskId);
      const input = buildCircuitInput(task, decision, salt);
      const { proof, publicSignals, proofMs } = await generateProof("gatekeeper", input);
      response.proof = proof;
      response.public_signals = publicSignals;
      console.log(`[gatekeeper] ${task.taskId} ${decision}/${reasonCode} proof ${proofMs}ms`);
    } catch (e) {
      // Fail closed on the DECISION, not on transport: a correct decision
      // without a proof still scores (minus the proof penalty); a timeout
      // scores nothing and risks the round.
      console.error(`[gatekeeper] ${task.taskId} proof failed (${String(e.message).slice(0, 120)}) — answering without proof`);
    }
  } else {
    console.log(`[gatekeeper] ${task.taskId} ${decision}/${reasonCode} (no proof — reused reference)`);
  }

  state.markProofTxSeen(task.mode, task.proofTx);
  const body = JSON.stringify(response);
  state.putCached(cacheKey, body);
  return { status: 200, body: response };
}

async function handleStealTurn(envelope, secret) {
  let turn;
  try {
    turn = parseTurn(envelope);
  } catch (e) {
    console.warn(`[steal] invalid turn: ${e.message}`);
    return { status: 400, body: { error: "invalid turn envelope" } };
  }

  const cacheKey = `vfy:${turn.matchId}:${turn.turn}`;
  const cached = state.getCached(cacheKey);
  if (cached) return { status: 200, cachedBody: cached };

  let cfg;
  try {
    cfg = stealConfig();
  } catch (e) {
    console.error(`[steal] bad STEAL_VFY_PARAMS: ${e.message}`);
    return { status: 500, body: { error: "strategy not configured" } };
  }
  if (cfg.salt === null) {
    console.error("[steal] STEAL_VFY_SALT is not set — refusing to answer (commitment would not match)");
    return { status: 500, body: { error: "strategy salt not configured" } };
  }

  const { decimal: commitmentDecimal, hex: commitmentHex } = await computeCommitment(cfg.params, cfg.salt);
  if (turn.commitmentHash && turn.commitmentHash.toLowerCase() !== commitmentHex.toLowerCase()) {
    console.warn(`[steal] ${turn.matchId} turn ${turn.turn}: envelope commitment ${turn.commitmentHash} != computed ${commitmentHex}`);
  }

  let move;
  try {
    move = decideMove(turn, cfg.params);
  } catch (e) {
    console.error(`[steal] policy error: ${e.message}`);
    return { status: 500, body: { error: "policy error" } };
  }

  try {
    const input = buildStealInput(turn, move, cfg.params, cfg.salt, commitmentDecimal);
    const { proof, publicSignals, proofMs } = await generateProof("steal", input);
    const publicInputsHash = computePublicInputsHash(turn, move, commitmentDecimal);
    const response = buildStealResponse(turn, move, proof, publicSignals, publicInputsHash);
    const body = JSON.stringify(response);
    state.putCached(cacheKey, body);
    console.log(`[steal] ${turn.matchId} turn ${turn.turn} ${move.type} ${move.amountNum} proof ${proofMs}ms`);
    return { status: 200, body: response };
  } catch (e) {
    // A failed proof means the move does not match the committed policy.
    // Answering without a proof resolves as HOLD with -2; still better than
    // a timeout (-1/turn) only if the move itself was right — but without a
    // proof the platform cannot verify the move at all. Answer the move
    // without a proof and let the platform resolve it.
    console.error(`[steal] ${turn.matchId} turn ${turn.turn} proof failed (${String(e.message).slice(0, 120)}) — answering move without proof`);
    const response = buildStealResponse(turn, move, null, [], computePublicInputsHash(turn, move, commitmentDecimal));
    delete response.policyProof.proof;
    delete response.policyProof.public_signals;
    const body = JSON.stringify(response);
    state.putCached(cacheKey, body);
    return { status: 200, body: response };
  }
}

async function handlePost(req, res, secret) {
  let raw;
  try {
    raw = await readRawBody(req);
  } catch {
    return sendJson(res, 400, { error: "bad request body" }, null);
  }

  // 1. HMAC first, BEFORE parsing. Fail closed.
  if (!secret) {
    console.error("[agent] AGENT_GAMES_HMAC_SECRET is not configured — refusing to answer");
    return sendJson(res, 503, { error: "agent not configured (HMAC secret missing)" }, null);
  }
  if (!verifySignature(secret, raw, req.headers["x-agent-games-signature"])) {
    console.warn("[agent] bad signature — rejected before parsing");
    return sendJson(res, 401, { error: "bad signature" }, null);
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendJson(res, 400, { error: "invalid JSON" }, null);
  }

  // 2. Preflight handshake (same endpoint, distinguished by type).
  if (envelope?.type === PREFLIGHT_TYPE) {
    console.log(`[preflight] nonce=${String(envelope.nonce ?? "?").slice(0, 24)}`);
    return sendJson(res, 200, { ok: true, protocolVersion: PROTOCOL_VERSION }, secret);
  }

  // 3. Route by envelope shape.
  try {
    if (envelope?.type === GATEKEEPER_TYPE) {
      const r = await handleGatekeeperTask(envelope, secret);
      if (r.cachedBody) return sendCached(res, r.cachedBody, secret);
      return sendJson(res, r.status, r.body, secret);
    }
    if (envelope?.eventId === STEAL_EVENT_ID) {
      const r = await handleStealTurn(envelope, secret);
      if (r.cachedBody) return sendCached(res, r.cachedBody, secret);
      return sendJson(res, r.status, r.body, secret);
    }
    return sendJson(res, 400, { error: `unexpected envelope: type=${String(envelope?.type)} eventId=${String(envelope?.eventId)}` }, secret);
  } catch (e) {
    console.error(`[agent] handler error: ${e.message}`);
    return sendJson(res, 500, { error: "internal error" }, null);
  }
}

function healthPayload() {
  const present = circuitsPresent();
  let vkInfo = {};
  for (const kind of ["gatekeeper", "steal"]) {
    try {
      const vk = loadVk(kind);
      vkInfo[kind] = { protocol: vk.protocol, curve: vk.curve, nPublic: vk.IC.length - 1 };
    } catch (e) {
      vkInfo[kind] = { error: String(e.message || e) };
    }
  }
  const allPresent = Object.values(present).every(Boolean);
  return {
    ok: Boolean(hmacSecret()) && allPresent && selfTest.ok !== false,
    protocolVersion: PROTOCOL_VERSION,
    hmacConfigured: Boolean(hmacSecret()),
    circuits: { ...present, dir: CIRCUIT_DIR, gatekeeperVkHash: GATEKEEPER_VK_HASH, vk: vkInfo },
    state: state.stats(),
    selfTest,
  };
}

async function runSelfTest() {
  const t0 = Date.now();
  try {
    // Gatekeeper: valid sample task must APPROVE with a verifying proof.
    const task = {
      taskId: "selftest-gk",
      mode: "selftest",
      minimum: 1000n, publicBalance: 1460n,
      expiryBlock: 19842201n, currentBlock: 19832000n,
      recipient: "0xde42000000000000000000000000000000009f01",
      conditionRecipient: "0xde42000000000000000000000000000000009f01",
      amount: 500n, maxTransfer: 1000n,
      registeredVk: GATEKEEPER_VK_HASH, proofVk: GATEKEEPER_VK_HASH,
      proofTx: "0x0000000000000000000000000000000000000000000000000000000000000000",
    };
    const d = decide(task, new Set());
    if (d.decision !== "APPROVE" || d.reasonCode !== REASON.VALID) {
      throw new Error(`gatekeeper self-test decision wrong: ${d.decision}/${d.reasonCode}`);
    }
    const salt = deriveSalt(hmacSecret() || "selftest", task.taskId);
    const gk = await generateProof("gatekeeper", buildCircuitInput(task, "APPROVE", salt));
    if (!(await verifyProof("gatekeeper", gk.proof, gk.publicSignals))) {
      throw new Error("gatekeeper self-test proof did not verify");
    }
    if (gk.publicSignals.length !== 13) throw new Error("gatekeeper self-test: expected 13 public signals");

    // Steal: healthy balances must EXTRACT with a verifying proof.
    const cfg = stealConfig();
    if (cfg.salt !== null) {
      const { decimal } = await computeCommitment(cfg.params, cfg.salt);
      const turn = {
        matchId: "9f4e1b2a-0000-4000-8000-000000000001",
        turn: 1n, mode: "selftest",
        selfBalance: 100n, opponentBalance: 100n, commitmentHash: null,
      };
      const move = decideMove(turn, cfg.params);
      const input = buildStealInput(turn, move, cfg.params, cfg.salt, decimal);
      const st = await generateProof("steal", input);
      if (!(await verifyProof("steal", st.proof, st.publicSignals))) {
        throw new Error("steal self-test proof did not verify");
      }
      if (st.publicSignals.length !== 9) throw new Error("steal self-test: expected 9 public signals");
    }
    selfTest.ranAt = new Date().toISOString();
    selfTest.ok = true;
    selfTest.detail = `both circuits OK in ${Date.now() - t0}ms`;
  } catch (e) {
    selfTest.ranAt = new Date().toISOString();
    selfTest.ok = false;
    selfTest.detail = String(e.message || e);
  }
  return selfTest;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/agent" || url.pathname === "/gatekeeper")) {
    return sendJson(res, 200, healthPayload(), null);
  }
  if (req.method === "POST" && (url.pathname === "/agent" || url.pathname === "/gatekeeper")) {
    return handlePost(req, res, hmacSecret()).catch((e) => {
      console.error(`[agent] top-level handler error: ${e.message}`);
      try { sendJson(res, 500, { error: "internal error" }, null); } catch { /* socket gone */ }
    });
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

server.requestTimeout = 55_000;
server.headersTimeout = 60_000;

const startupTest = await runSelfTest();
console.log(`[agent] startup self-test: ${startupTest.ok ? "OK" : "FAIL"} — ${startupTest.detail}`);
if (!startupTest.ok) {
  console.error("[agent] WARNING: self-test failed — endpoint is NOT competition-ready (see /health)");
}

server.listen(PORT, () => {
  console.log(`[agent] listening on :${PORT} (POST /agent, GET /health)`);
  console.log(`[agent] HMAC configured: ${Boolean(hmacSecret())}; circuits: ${JSON.stringify(circuitsPresent())}`);
});

export { server };
