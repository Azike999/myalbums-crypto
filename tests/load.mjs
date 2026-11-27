// Loads ../crypto.js exactly as the browser does (unchanged file) and returns window.PBCrypto.
// Optional `seed`: replaces crypto.getRandomValues with a deterministic stream so that
// encryption outputs (IVs, keys, salts) are reproducible for test vectors.
// Only getRandomValues is replaced; all cryptography is Node's standard WebCrypto (crypto.subtle).
import fs from "node:fs";
import vm from "node:vm";
import { webcrypto, createHash } from "node:crypto";

export function seededRandom(seed) {
  let counter = 0, pool = new Uint8Array(0);
  return (arr) => {
    const out = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    let filled = 0;
    while (filled < out.length) {
      if (!pool.length) pool = new Uint8Array(createHash("sha256").update(`${seed}:${counter++}`).digest());
      const take = Math.min(pool.length, out.length - filled);
      out.set(pool.subarray(0, take), filled); pool = pool.subarray(take); filled += take;
    }
    return arr;
  };
}

export function loadPBCrypto(seed) {
  const src = fs.readFileSync(new URL("../crypto.js", import.meta.url), "utf8");
  const fake = {
    subtle: webcrypto.subtle,
    getRandomValues: seed ? seededRandom(seed) : (a) => webcrypto.getRandomValues(a),
  };
  Object.defineProperty(globalThis, "crypto", { value: fake, configurable: true, writable: true });
  globalThis.window = globalThis;
  delete globalThis.PBCrypto;
  // lib/noble-p256.js: the browser runs it only if its SHA-256 equals the one written in crypto.js (SRI) - same check here
  const lib = fs.readFileSync(new URL("../lib/noble-p256.js", import.meta.url));
  const sri = "sha256-" + createHash("sha256").update(lib).digest("base64");
  if (!src.includes(`LINK_LIB_SRI = "${sri}"`)) throw new Error("lib/noble-p256.js does not match the SRI hash in crypto.js");
  if (!globalThis.nobleP256) vm.runInThisContext(lib.toString("utf8"), { filename: "lib/noble-p256.js" });
  vm.runInThisContext(src, { filename: "crypto.js" });
  return globalThis.PBCrypto;
}

export const hex = (u) => Buffer.from(u).toString("hex");
export const b64 = (u) => Buffer.from(u).toString("base64");
export const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
export const sha256hex = (u) => createHash("sha256").update(u).digest("hex");
// Test file for the chunked format: byte i = (i * 31 + 7) mod 251, length 2.5 MiB + 123 (3 chunks, last one partial)
export const CHUNKED_LEN = 2621563;
export function chunkedPlain(n = CHUNKED_LEN) { const u = new Uint8Array(n); for (let i = 0; i < n; i++) u[i] = (i * 31 + 7) % 251; return u; }
