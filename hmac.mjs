// HMAC-SHA256 for the x-agent-games-signature header.
// Spec facts (official /build page + verified live by independent participants):
// - Sign/verify over the RAW request/response body bytes, BEFORE JSON parsing.
// - Digest is lowercase hex. The secret is used verbatim as the HMAC key.
// - Inbound verification tolerates hex, base64, and an optional "sha256="
//   prefix — same MAC bytes, different representation. Still constant-time.
import { createHmac, timingSafeEqual } from "node:crypto";

export function hmacHex(secret, rawBody) {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

function decodeCandidate(headerValue) {
  let v = headerValue.trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch { /* not base64 */ }
  return null;
}

export function verifySignature(secret, rawBody, headerValue) {
  if (!secret || typeof headerValue !== "string") return false;
  const candidate = decodeCandidate(headerValue);
  if (!candidate) return false;
  const expected = createHmac("sha256", secret).update(rawBody).digest();
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}
