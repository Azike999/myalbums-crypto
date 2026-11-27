// Checks test_vectors.json against the real crypto.js (Node 20+):
//   node tests/check_vectors.mjs
// 1) deterministic part: re-encrypts with the same seeded random stream -> must match byte for byte;
// 2) every vector is also decrypted back with a freshly loaded crypto.js (normal random source).
import fs from "node:fs";
import { loadPBCrypto, hex, b64, fromB64, sha256hex, chunkedPlain } from "./load.mjs";
import { SEED, deterministic } from "./make_vectors.mjs";

const V = JSON.parse(fs.readFileSync(new URL("../test_vectors.json", import.meta.url), "utf8"));
let fails = 0, oks = 0;
const ok = (cond, name, extra = "") => { if (cond) oks++; else { fails++; console.log("FAIL", name, extra); } };
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// 1. same seed -> same output
const again = await deterministic(loadPBCrypto(SEED));
for (const k of Object.keys(V.deterministic)) ok(eq(again[k], V.deterministic[k]), `re-encrypt: ${k}`);

// 2. decrypt direction with normal randomness
const C = loadPBCrypto(null), D = V.deterministic, E = V.ecdh;
await C.fromRecoveryCode(D.recovery_code_typed);
ok(hex(fromB64(C.exportB64())) === D.master_key_hex, "recovery code (typed by a human) -> master key");
ok(C.recoveryCode() === D.recovery_code, "master key -> recovery code");
ok(new TextDecoder().decode(await C.decryptBytes(fromB64(D.encrypt_bytes.ciphertext_b64))) === D.encrypt_bytes.plaintext_utf8, "decryptBytes");
ok(eq(await C.decryptJSON(D.encrypt_json.ciphertext_b64), D.encrypt_json.object), "decryptJSON");
ok(await C.dedupTag(new TextEncoder().encode(D.dedup_tag.data_utf8)) === D.dedup_tag.tag_b64, "dedupTag (HMAC, deterministic)");
{ // streamed HMAC = one-shot HMAC
  const h = C.dedupStream(); const t = new TextEncoder().encode(D.dedup_tag.data_utf8); h.update(t.subarray(0, 5)); h.update(t.subarray(5));
  ok(h.digestB64() === D.dedup_tag.tag_b64, "dedupStream (pure-JS SHA-256 in parts) = dedupTag");
}
{ // chunked: fresh encryption has a new random header, but decrypts to the same file
  const plain = chunkedPlain(), ct = await C.encryptBytesChunked(plain);
  ok(ct.length === D.chunked.ciphertext_len, "chunked: ciphertext length");
  ok(sha256hex(await C.decryptBytes(ct)) === D.chunked.plaintext_sha256, "chunked: decrypt = plaintext");
  const bad = ct.slice(); bad[40] ^= 1; let threw = false; try { await C.decryptBytes(bad); } catch { threw = true; }
  ok(threw, "chunked: one flipped bit -> refused (GCM)");
  const cut = ct.slice(0, ct.length - 16 - 100); threw = false; try { await C.decryptBytes(cut); } catch { threw = true; }
  ok(threw, "chunked: truncated file -> refused");
}
{
  const fk = await C.fileKey(D.file_key.key_b64);
  ok(new TextDecoder().decode(await C.decryptBytes(fromB64(D.file_key.encrypt_bytes_b64), fk)) === D.encrypt_bytes.plaintext_utf8, "file key decrypt");
}
{
  const s = D.secret_album, k = await C.unlockAlbumKey(s.password, s.salt_b64, s.wrapped_b64);
  ok(C.rawB64(k) === s.album_key_b64, "secret album: password -> album key");
  ok(await C.albumTag(D.dedup_tag.tag_b64, k) === s.album_tag_b64, "secret album: albumTag");
  let threw = false; try { await C.unlockAlbumKey(s.password + "x", s.salt_b64, s.wrapped_b64); } catch { threw = true; }
  ok(threw, "secret album: wrong password -> refused");
}
{
  const m = E.member, priv = await C.openUserPriv(m.member_priv_enc_b64), k = await C.unwrapForMe(m.wrapped, priv);
  ok(C.rawB64(k) === m.album_key_b64, "shared album: member unwraps album key (ECDH P-256 + HKDF + AES-GCM)");
  ok(await C.safetyCode(m.member_pub_spki_b64) === m.safety_code, "shared album: safety code");
}
{
  const d = E.device_link;
  ok(hex(fromB64(await C.linkOpen(d.wrapped, d.device_priv_pkcs8_b64))) === D.master_key_hex, "device link: new device opens master key");
  ok(await C.linkCheck(d.device_pub_spki_b64) === d.link_check, "device link: 4-digit check");
}
{
  const h = E.heir;
  const { webcrypto } = await import("node:crypto");
  const priv = await webcrypto.subtle.importKey("pkcs8", fromB64(h.heir_priv_pkcs8_b64), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  ok(hex(fromB64(await C.heirOpen(h.env, h.share_b, h.share_a_enc, priv))) === D.master_key_hex, "trusted person: A + B -> master key");
}
console.log(fails ? `${fails} FAILED, ${oks} passed` : `all ${oks} checks passed`);
process.exit(fails ? 1 : 0);
