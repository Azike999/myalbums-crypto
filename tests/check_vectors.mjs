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
  ok(await C.pubFromPrivEnc(m.member_priv_enc_b64) === m.member_pub_spki_b64 && m.pub_from_priv_enc === m.member_pub_spki_b64, "own public key derived from own private key");
}
{ // device link by code: SPAKE2 (RFC 9382) - first the official test vectors of the RFC, then ours
  const R = JSON.parse(fs.readFileSync(new URL("./rfc9382_vectors.json", import.meta.url), "utf8")).vectors;
  for (const r of R) {
    const o = await C.spake2Vector(r.A, r.B, r.w, r.x, r.y);
    const bad = ["pA", "pB", "K", "TT", "Ke", "Ka", "KcA", "KcB", "cA", "cB"].filter((k) => o[k] !== r[k]);
    ok(!bad.length && o.bothSides, `RFC 9382 Appendix B, A='${r.A}' B='${r.B}': every intermediate value`, bad.join(","));
  }
  const d = D.device_link, st = { code: d.code, x: d.x_hex };
  ok(/^\d{6}$/.test(d.code) && /^\d{6}$/.test(C.linkCode()), "device link: the code is 6 digits");
  ok(hex(fromB64(await C.linkFinish(st, d.answer_b))) === D.master_key_hex, "device link: right code -> new device gets the master key");
  const other = d.code === "000000" ? "000001" : "000000";
  let err = ""; try { await C.linkFinish({ code: other, x: d.x_hex }, d.answer_b); } catch (e) { err = e.message; }
  ok(err === "link_code", "device link: wrong code on the device -> refused (confirmation cB differs)");
  err = ""; try { await C.linkFinish(st, await C.linkAnswer(other, d.message_a)); } catch (e) { err = e.message; }
  ok(err === "link_code", "device link: wrong code typed in Telegram -> refused");
  const parts = d.answer_b.split("."), box = fromB64(parts[3]); box[20] ^= 1; parts[3] = b64(box);
  err = ""; try { await C.linkFinish(st, parts.join(".")); } catch (e) { err = e.message || "gcm"; }
  ok(err !== "", "device link: one flipped bit in the locked key -> refused (GCM)");
  err = ""; try { await C.linkAnswer(d.code, "A".repeat(124)); } catch (e) { err = e.message; }
  ok(err === "link_old", "device link: an old-style request (public key, 4-digit check) is not answered");
  const pt = fromB64(d.message_a.slice(3)); pt[40] ^= 1;               // a point that is not on the curve
  err = ""; try { await C.linkAnswer(d.code, "S1." + b64(pt)); } catch (e) { err = e.message || "bad point"; }
  ok(err !== "", "device link: a point that is not on the curve is rejected (RFC 9382, section 7)");
}
{
  const h = E.heir;
  const { webcrypto } = await import("node:crypto");
  const priv = await webcrypto.subtle.importKey("pkcs8", fromB64(h.heir_priv_pkcs8_b64), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  ok(hex(fromB64(await C.heirOpen(h.env, h.share_b, h.share_a_enc, priv))) === D.master_key_hex, "trusted person: A + B -> master key");
  ok(await C.heirCode(h.heir_pub_spki_b64) === h.heir_code && /^\d{4} \d{4} \d{4} \d{4}$/.test(h.heir_code), "trusted person: 16-digit check code");
}
console.log(fails ? `${fails} FAILED, ${oks} passed` : `all ${oks} checks passed`);
process.exit(fails ? 1 : 0);
