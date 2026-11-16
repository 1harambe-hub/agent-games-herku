// Print the Steal-the-VFY strategy commitment for the dashboard form.
// The commitment MUST be computed from the exact STEAL_VFY_PARAMS + STEAL_VFY_SALT
// the running agent uses, or every turn proof fails. Run with the same env:
//   STEAL_VFY_PARAMS="10,20,0,0,0,0,0,0" STEAL_VFY_SALT="..." node commitment.mjs
import { stealConfig } from "./config.mjs";
import { computeCommitment } from "./steal.mjs";

const { params, salt } = stealConfig();
if (salt === null) {
  console.error("STEAL_VFY_SALT is not set. Pick a random decimal integer, keep it secret, and set it in the agent environment.");
  process.exit(1);
}
const c = await computeCommitment(params, salt);
console.log("Strategy params :", params.map(String).join(","));
console.log("Salt            :", salt.toString());
console.log("Commitment (hex):", c.hex);
console.log("Commitment (dec):", c.decimal);
console.log("Circuit version : v1");
process.exit(0);
