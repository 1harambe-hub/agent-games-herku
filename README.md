# Agent Games arena agent — `herku`

A dual-track agent for zkVerify Agent Games Season 01: **Proof Gatekeeper**
and **Steal the VFY**. Plain Node.js, no framework. It receives HMAC-signed
tasks, decides deterministically (no LLM anywhere near a decision), and
generates a Groth16 proof locally with snarkjs for every provable decision.

Built and verified locally on 2026-11-16. **Not yet deployed** — the build
VM has no public IP and no working no-account tunnel (see Deployment).

## What is verified (not claimed)

- Both official circuits proven locally with snarkjs against the exported
  verification keys: gatekeeper (13 public signals), vfy-policy (9).
- The circuit is the referee: wrong decisions fail witness generation
  (tested: trap+APPROVE fails, valid+REJECT fails, wrong Steal action fails).
- Expiry edge found empirically: `currentBlock == expiryBlock` counts as
  EXPIRED (the circuit refuses APPROVE at equality).
- `node test_local.mjs`: **56/56 checks pass** — preflight, HMAC gating,
  all 7 trap types + boundaries, proof verification, proof-reuse handling,
  idempotent redelivery, Steal extract/fortify turns.
- Commitment formula confirmed: gatekeeper public signal 0 is
  `Poseidon(salt, taskId)`; Steal commitment is `Poseidon(params[0..7], salt)`.

## Layout

| File | Purpose |
|---|---|
| `server.mjs` | HTTP endpoint: `POST /agent`, `GET /health` |
| `gatekeeper.mjs` | Task parsing, deterministic decisions, circuit inputs |
| `steal.mjs` | Turn parsing, committed policy, commitment math |
| `prover.mjs` | snarkjs wrappers with timeout |
| `hmac.mjs` | `x-agent-games-signature` sign/verify (hex, raw body) |
| `field.mjs` | Field-element encodings (hashes mod prime, UTF-8 task IDs) |
| `state.mjs` | Seen proof-refs (per mode) + idempotency cache, persisted JSON |
| `config.mjs` | Env-driven configuration |
| `commitment.mjs` | Prints the Steal strategy commitment hex for the dashboard |
| `test_local.mjs` | End-to-end harness simulating the platform |
| `circuits/` | Official artifacts from agentgames.zkverify.io + exported VKs |

## Run locally

```sh
npm install
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET + STEAL_VFY_SALT
node server.mjs        # POST /agent, GET /health
node test_local.mjs    # 56 checks, no network needed
node commitment.mjs    # Steal commitment hex (same env as the server)
```

## Deployment (Railway, free trial)

The agent must live at a public HTTPS URL — the platform POSTs tasks to it.
Railway is the recommended host (GitHub login, free trial credit covers a
tiny Node service for the remaining competition days).

1. Push this directory to a **new public GitHub repo** (e.g.
   `agent-games-herku`). Do NOT commit `.env` or `state.json`.
2. On [railway.app](https://railway.app): New Project → Deploy from GitHub
   repo → pick the repo. Railway auto-detects Node and runs `npm start`.
3. In the service → Settings → Networking → **Generate Domain**. Your
   endpoint is `https://<domain>/agent`.
4. On the Agent Games dashboard → My Agents → **Register agent**: name,
   events (Proof Gatekeeper + Steal the VFY), repo URL, endpoint URL
   (`https://<domain>/agent`). Submit.
5. Dashboard → agent → **Rotate Secret**. Copy the one-time plaintext.
6. Railway → service → Variables: set `AGENT_GAMES_HMAC_SECRET` to the
   pasted secret, `STEAL_VFY_PARAMS=10,20,0,0,0,0,0,0`, and `STEAL_VFY_SALT`
   to a random decimal integer you keep. Redeploy/restart.
7. Dashboard → agent → **Run preflight**. Must pass (10s window).
8. Dashboard → Practice → dispatch a Proof Gatekeeper task and a Steal turn.
   Confirm decisions + VERIFIED proofs.
9. Dashboard → Enter the arena: enter both events.
10. Steal only: run `node commitment.mjs` with the SAME params+salt as the
    deployment, then Dashboard → My Agents → Edit agent → Steal the VFY
    section → register the strategy commitment (hex, circuitVersion `v1`,
    policyVersion `v1`) BEFORE the next Swiss round pairs.

Optional but recommended: attach a Railway volume and set
`STATE_FILE=/app/data/state.json` so the proof-reuse memory survives
restarts. Without it, a restart wipes the seen-set (a reused proof_tx in a
later task could then be mis-approved).

## Prize eligibility (separate, dashboard)

- Connect GitHub on the dashboard (Rules §1.1, one GitHub per account).
- Bind a Substrate/SS58 payout wallet in Settings — the EVM wallet alone
  does not receive VFY prizes.

## Honest status

- Gatekeeper rounds 1–3 are done; a new entrant starts 3 rounds behind on a
  cumulative board with 144+ agents. Top 3 is a long shot; verified proofs
  are the differentiator (most responses in rounds 1–3 were unverified).
- Steal the VFY has a tiny field (9 agents paired at last check) and
  mid-tournament entry joins the next Swiss round — the realistic shot,
  if deployed before the next round pairs.
- No Kurier integration: proofs are returned to the platform, which
  re-verifies them offline. `proof_tx` in responses echoes the task's
  reference. Nothing is spent on-chain.
  redeploy
