// Generates ../test_vectors.json by running the real crypto.js.
//   node tests/make_vectors.mjs
// "deterministic" vectors: random bytes come from a seeded stream, so re-running gives the same output
// (check_vectors.mjs re-encrypts and compares byte for byte).
// "ecdh" vectors: ECDH key pairs are generated inside WebCrypto and cannot be seeded, so these are
// checked in the decrypt direction (given the recipient's private key -> expected plaintext).
import fs from "node:fs";
import { webcrypto } from "node:crypto";
import { loadPBCrypto, hex, b64, fromB64, sha256hex, chunkedPlain, CHUNKED_LEN } from "./load.mjs";

export const SEED = "myalbums-crypto test vectors v1";
export const PASSWORD = "Пароль-тест 1 ﬁ";             // non-ASCII + a ligature: checks NFKC normalisation
export const TEXT = "Привет, My Albums! 👋";
export const META = { cap: "Подпись к фото", taken: "2026-11-27T10:00:00", geo: [48.8584, 2.2945], people: ["Alice"] };

export async function deterministic(C) {
  const v = {};
  await C.generate();
  const master = fromB64(C.exportB64());
  v.master_key_hex = hex(master);
  v.recovery_code = C.recoveryCode();
  // the same code typed by a human: lower case, no dashes, 0/1/8 and Cyrillic look-alikes
  v.recovery_code_typed = v.recovery_code.toLowerCase().replace(/-/g, " ").replace(/o/g, "0").replace(/i/g, "1").replace(/b/g, "8").replace(/a/g, "а").replace(/e/g, "е");

  const text = new TextEncoder().encode(TEXT);
  v.encrypt_bytes = { plaintext_utf8: TEXT, ciphertext_b64: b64(await C.encryptBytes(text)) };
  v.encrypt_json = { object: META, ciphertext_b64: await C.encryptJSON(META) };
  v.dedup_tag = { data_utf8: TEXT, tag_b64: await C.dedupTag(text) };

  const plain = chunkedPlain();
  const ct = await C.encryptBytesChunked(plain);
  v.chunked = { plaintext: `byte i = (i*31+7) mod 251, length ${CHUNKED_LEN}`, plaintext_len: CHUNKED_LEN,
                plaintext_sha256: sha256hex(plain), ciphertext_len: ct.length, header_hex: hex(ct.subarray(0, 32)),
                ciphertext_sha256: sha256hex(ct) };

  const fk = await C.newFileKey();
  v.file_key = { key_b64: fk.raw, encrypt_bytes_b64: b64(await C.encryptBytes(text, fk.key)) };

  const al = await C.newAlbumKey(PASSWORD);
  v.secret_album = { password: PASSWORD, pbkdf2_iterations: 300000, salt_b64: al.salt, wrapped_b64: al.wrapped,
                     album_key_b64: C.rawB64(al.key),
                     album_tag_b64: await C.albumTag(v.dedup_tag.tag_b64, al.key) };

  const sh = await C.newSharedKey();
  v.shared_album = { shared_key_b64: sh.raw, wrapped_by_master_b64: await C.wrapSharedKey(sh.key), share_code: C.shareCode() };

  // device link by code (SPAKE2, RFC 9382): the new device's 6 digits, its secret scalar x and both messages.
  // x comes from the seeded stream too, so this part is reproducible byte for byte.
  const code = C.linkCode(), a = await C.linkStart(code);
  v.device_link = { code, x_hex: a.state.x, message_a: a.msg, answer_b: await C.linkAnswer(code, a.msg) };
  return v;
}

export async function ecdh(C) {
  const v = {};
  const user = await C.newUserPair();                                    // album member
  const sh = await C.newSharedKey();
  v.member = { member_pub_spki_b64: user.pub, member_priv_enc_b64: user.priv_enc,
               album_key_b64: sh.raw, wrapped: await C.wrapForMember(sh.key, user.pub),
               safety_code: await C.safetyCode(user.pub),
               pub_from_priv_enc: await C.pubFromPrivEnc(user.priv_enc) };   // public half derived from the private one
  // trusted person ("two of two"): in the app this is the person's own key pair; here a fresh P-256 pair
  const kp = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const heir = { pub: b64(await webcrypto.subtle.exportKey("spki", kp.publicKey)), priv: b64(await webcrypto.subtle.exportKey("pkcs8", kp.privateKey)) };
  const seal = await C.heirSeal(heir.pub);
  v.heir = { heir_pub_spki_b64: heir.pub, heir_priv_pkcs8_b64: heir.priv, heir_code: await C.heirCode(heir.pub), ...seal };
  return v;
}

if ((process.argv[1] || "").endsWith("make_vectors.mjs")) {
  const C = loadPBCrypto(SEED);
  const out = { about: "Test vectors produced by crypto.js (see tests/make_vectors.mjs). Binary values: hex or base64.",
                seed: SEED, crypto_js_sha256: sha256hex(fs.readFileSync(new URL("../crypto.js", import.meta.url))),
                noble_p256_sha256: sha256hex(fs.readFileSync(new URL("../lib/noble-p256.js", import.meta.url))),
                deterministic: await deterministic(C), ecdh: await ecdh(C) };
  fs.writeFileSync(new URL("../test_vectors.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
  console.log("test_vectors.json written");
}
