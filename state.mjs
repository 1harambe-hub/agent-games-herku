// Durable agent state: proof-reference seen-set (per mode) and idempotency
// cache (task_id / match+turn -> exact response body). Persisted to a JSON
// file with atomic rename. The platform may retry deliveries after network
// failures, so replays MUST return the identical response body.
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { STATE_FILE } from "./config.mjs";

export class StateStore {
  constructor(file = STATE_FILE) {
    this.file = file;
    this.seen = new Set(); // "mode:proofTx"
    this.cache = new Map(); // key -> response body string
    this.load();
  }

  load() {
    try {
      if (!existsSync(this.file)) return;
      const data = JSON.parse(readFileSync(this.file, "utf8"));
      if (Array.isArray(data.seen)) this.seen = new Set(data.seen);
      if (data.cache && typeof data.cache === "object") {
        this.cache = new Map(Object.entries(data.cache));
      }
    } catch (e) {
      console.error(`[state] could not load ${this.file}: ${e.message} — starting empty`);
    }
  }

  save() {
    try {
      const tmp = `${this.file}.tmp`;
      writeFileSync(tmp, JSON.stringify({ seen: [...this.seen], cache: Object.fromEntries(this.cache) }));
      renameSync(tmp, this.file);
    } catch (e) {
      console.error(`[state] could not persist ${this.file}: ${e.message}`);
    }
  }

  hasSeenProofTx(mode, proofTx) {
    return this.seen.has(`${mode}:${proofTx}`);
  }

  markProofTxSeen(mode, proofTx) {
    this.seen.add(`${mode}:${proofTx}`);
    this.save();
  }

  getCached(key) {
    return this.cache.get(key) ?? null;
  }

  putCached(key, body) {
    this.cache.set(key, body);
    this.save();
  }

  stats() {
    return { seenProofRefs: this.seen.size, cachedResponses: this.cache.size };
  }
}
