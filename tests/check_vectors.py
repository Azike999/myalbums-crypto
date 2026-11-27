# -*- coding: utf-8 -*-
"""Independent check of test_vectors.json — written from SPEC.md, does NOT use crypto.js.

    pip install cryptography
    python tests/check_vectors.py

If this script and crypto.js agree, the format in SPEC.md is what the code really does."""
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import unicodedata

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = os.path.dirname(os.path.abspath(__file__))
V = json.load(open(os.path.join(HERE, "..", "test_vectors.json"), encoding="utf-8"))
D, E = V["deterministic"], V["ecdh"]
b64 = lambda s: base64.b64decode(s)
fails = oks = 0


def ok(cond, name):
    global fails, oks
    if cond:
        oks += 1
    else:
        fails += 1
        print("FAIL", name)


# --- primitives as described in SPEC.md -----------------------------------------------------------
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
LOOK = dict(zip("АВЕКМНОРСТХ", "ABEKMHOPCTX"))


def b32enc(b):
    bits = val = 0
    out = ""
    for x in b:
        val = (val << 8) | x
        bits += 8
        while bits >= 5:
            out += B32[(val >> (bits - 5)) & 31]
            bits -= 5
    if bits:
        out += B32[(val << (5 - bits)) & 31]
    return out


def b32dec(s):
    s = "".join(LOOK.get(c, c) for c in s.upper()).replace("0", "O").replace("1", "I").replace("8", "B")
    s = "".join(c for c in s if c in B32)
    bits = val = 0
    out = bytearray()
    for c in s:
        val = (val << 5) | B32.index(c)
        bits += 5
        if bits >= 8:
            out.append((val >> (bits - 8)) & 255)
            bits -= 8
    return bytes(out)


def dec(key, blob):                       # IV(12) || ciphertext+tag
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def dedup_key(key):
    return hashlib.sha256(key + b"dedup").digest()


def ecies_open(wrapped, priv):            # "E1.<eph pub raw>.<salt>.<iv>.<ct>"
    v, e, s, i, c = wrapped.split(".")
    assert v == "E1"
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64(e))
    shared = priv.exchange(ec.ECDH(), pub)
    k = HKDF(hashes.SHA256(), 32, b64(s), b"myalbums-shared-v1").derive(shared)
    return AESGCM(k).decrypt(b64(i), b64(c), None)


def chunked_encrypt(key, header, plain, chunk=1 << 20):
    parts = [header]
    n = max(1, -(-len(plain) // chunk))
    for i in range(n):
        iv = header[16:24] + struct.pack(">I", i)
        aad = header + struct.pack(">I", i)
        parts.append(AESGCM(key).encrypt(iv, plain[i * chunk:(i + 1) * chunk], aad))
    return b"".join(parts)


# --- checks --------------------------------------------------------------------------------------
master = bytes.fromhex(D["master_key_hex"])
ok("-".join(b32enc(master)[i:i + 4] for i in range(0, 52, 4)) == D["recovery_code"], "recovery code = base32(master)")
ok(b32dec(D["recovery_code_typed"])[:32] == master, "typed recovery code -> master")
ok(dec(master, b64(D["encrypt_bytes"]["ciphertext_b64"])).decode() == D["encrypt_bytes"]["plaintext_utf8"], "AES-GCM bytes")
ok(json.loads(dec(master, b64(D["encrypt_json"]["ciphertext_b64"]))) == D["encrypt_json"]["object"], "AES-GCM JSON")
tag = hmac.new(dedup_key(master), D["dedup_tag"]["data_utf8"].encode(), hashlib.sha256).digest()
ok(base64.b64encode(tag).decode() == D["dedup_tag"]["tag_b64"], "dedup tag = HMAC-SHA256(SHA-256(key||'dedup'), data)")

c = D["chunked"]
plain = bytes((i * 31 + 7) % 251 for i in range(c["plaintext_len"]))
ok(hashlib.sha256(plain).hexdigest() == c["plaintext_sha256"], "chunked: test file")
hdr = bytes.fromhex(c["header_hex"])
ok(hdr[:4] == b"PBC1" and struct.unpack(">I", hdr[4:8])[0] == 1 << 20 and struct.unpack(">Q", hdr[8:16])[0] == len(plain)
   and hdr[24:32] == bytes(8), "chunked: header layout")
ct = chunked_encrypt(master, hdr, plain)
ok(len(ct) == c["ciphertext_len"] and hashlib.sha256(ct).hexdigest() == c["ciphertext_sha256"], "chunked: independent re-encryption matches")

ok(dec(b64(D["file_key"]["key_b64"]), b64(D["file_key"]["encrypt_bytes_b64"])).decode() == D["encrypt_bytes"]["plaintext_utf8"], "file key")

s = D["secret_album"]
kek = PBKDF2HMAC(hashes.SHA256(), 32, b64(s["salt_b64"]), s["pbkdf2_iterations"]).derive(
    unicodedata.normalize("NFKC", s["password"]).encode())
album = dec(kek, b64(s["wrapped_b64"]))
ok(album == b64(s["album_key_b64"]), "secret album: PBKDF2-SHA256 -> unwrap album key")
at = hmac.new(dedup_key(album), b64(D["dedup_tag"]["tag_b64"]), hashlib.sha256).digest()
ok(base64.b64encode(at).decode() == s["album_tag_b64"], "secret album: album tag")

sh = D["shared_album"]
ok(dec(master, b64(sh["wrapped_by_master_b64"])) == b64(sh["shared_key_b64"]), "shared key stored under master key")
ok(len(b32dec(sh["share_code"])) == 10, "share code = 80 bits")

m = E["member"]
priv = serialization.load_der_private_key(dec(master, b64(m["member_priv_enc_b64"])), None)
ok(ecies_open(m["wrapped"], priv) == b64(m["album_key_b64"]), "shared album: ECIES unwrap for member")
h = hashlib.sha256(b64(m["member_pub_spki_b64"])).digest()
n = int.from_bytes(h[:4], "big") * 3 + h[4] % 3
code = str(n % 10 ** 10).zfill(10)
ok(f"{code[:5]} {code[5:]}" == m["safety_code"], "safety code")

# --- device link by code: SPAKE2, RFC 9382 (P256-SHA256-HKDF-HMAC). Plain-integer P-256 written from the standard
# (slow, not constant-time - fine for a check), so this does not depend on the JS library crypto.js loads.
P_ = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
B_ = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N_ = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G_ = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def padd(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P_ == 0: return None
    if p == q: l = (3 * p[0] * p[0] - 3) * pow(2 * p[1], -1, P_) % P_
    else: l = (q[1] - p[1]) * pow(q[0] - p[0], -1, P_) % P_
    x = (l * l - p[0] - q[0]) % P_
    return x, (l * (p[0] - x) - p[1]) % P_


def pmul(k, p):
    r = None
    while k:
        if k & 1: r = padd(r, p)
        p, k = padd(p, p), k >> 1
    return r


def pneg(p): return (p[0], (-p[1]) % P_)


def pdec(b):
    x = int.from_bytes(b[1:33], "big")
    if b[0] == 4:
        y = int.from_bytes(b[33:], "big")
    else:
        y = pow((x ** 3 - 3 * x + B_) % P_, (P_ + 1) // 4, P_)
        if y % 2 != b[0] % 2: y = P_ - y
    assert (y * y - x ** 3 + 3 * x - B_) % P_ == 0, "not on the curve"
    return x, y


def penc(p): return b"\x04" + p[0].to_bytes(32, "big") + p[1].to_bytes(32, "big")


M_ = pdec(bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"))   # RFC 9382, section 6
N2 = pdec(bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"))
lenp = lambda b: len(b).to_bytes(8, "little") + b


def hkdf(ikm, info, n=32):
    return HKDF(hashes.SHA256(), n, None, info).derive(ikm)


def spake_keys(A, B, w, pA, pB, K):
    TT = lenp(A) + lenp(B) + lenp(pA) + lenp(pB) + lenp(K) + lenp(w.to_bytes(32, "big"))
    h = hashlib.sha256(TT).digest()
    kc = hkdf(h[16:], b"ConfirmationKeys")
    return {"TT": TT, "Ke": h[:16], "Ka": h[16:], "KcA": kc[:16], "KcB": kc[16:],
            "cA": hmac.new(kc[:16], TT, hashlib.sha256).digest(), "cB": hmac.new(kc[16:], TT, hashlib.sha256).digest()}


RFC = json.load(open(os.path.join(HERE, "rfc9382_vectors.json"), encoding="utf-8"))["vectors"]
for r in RFC:
    w, x, y = (int(r[k], 16) for k in "wxy")
    pA = penc(padd(pmul(x, G_), pmul(w, M_))); pB = penc(padd(pmul(y, G_), pmul(w, N2)))
    K = penc(pmul(x, padd(pdec(pB), pneg(pmul(w, N2)))))
    KB = penc(pmul(y, padd(pdec(pA), pneg(pmul(w, M_)))))
    k = spake_keys(r["A"].encode(), r["B"].encode(), w, pA, pB, K)
    got = {"pA": pA, "pB": pB, "K": K, **k}
    bad = [n for n in ("pA", "pB", "K", "TT", "Ke", "Ka", "KcA", "KcB", "cA", "cB") if got[n].hex() != r[n]]
    ok(not bad and K == KB, f"RFC 9382 Appendix B, A='{r['A']}' B='{r['B']}' (independent P-256): {bad}")

d = D["device_link"]
IDS = (b"myalbums-link-v1:device", b"myalbums-link-v1:telegram")
w = int.from_bytes(hashlib.sha512(b"myalbums-link-v1:w:" + d["code"].encode()).digest(), "big") % N_
x = int(d["x_hex"], 16)
pA = penc(padd(pmul(x, G_), pmul(w, M_)))
ok(d["message_a"] == "S1." + base64.b64encode(pA).decode(), "device link: message A = x*G + w*M, w = SHA-512(label || code) mod n")
v_, b_, c_, box = d["answer_b"].split(".")
pB = b64(b_)
k = spake_keys(*IDS, w, pA, pB, penc(pmul(x, padd(pdec(pB), pneg(pmul(w, N2))))))
ok(k["cB"] == b64(c_), "device link: confirmation cB = HMAC(KcB, TT) matches")
ok(dec(hkdf(k["Ke"], b"myalbums-link-v1:master"), b64(box)) == master, "device link: master key opened with HKDF(Ke)")
w2 = int.from_bytes(hashlib.sha512(b"myalbums-link-v1:w:" + (b"000001" if d["code"] == "000000" else b"000000")).digest(), "big") % N_
k2 = spake_keys(*IDS, w2, pA, pB, penc(pmul(x, padd(pdec(pB), pneg(pmul(w2, N2))))))
ok(k2["cB"] != b64(c_), "device link: with another code the confirmation does not match")

he = E["heir"]
h = hashlib.sha256(b64(he["heir_pub_spki_b64"])).digest()
c16 = str(int.from_bytes(h[:8], "big") % 10 ** 16).zfill(16)
ok(" ".join(c16[i:i + 4] for i in range(0, 16, 4)) == he["heir_code"], "trusted person: 16-digit check code = SHA-256(pub)[:8] mod 10^16")
mp = serialization.load_der_private_key(dec(master, b64(m["member_priv_enc_b64"])), None).public_key()
ok(mp.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == b64(m["member_pub_spki_b64"]), "public key derived from the private key = published one")
hpriv = serialization.load_der_private_key(b64(he["heir_priv_pkcs8_b64"]), None)
A = ecies_open(he["share_a_enc"], hpriv)
B = b64(he["share_b"])
Ekey = bytes(x ^ y for x, y in zip(A, B))
ok(dec(Ekey, b64(he["env"])) == master, "trusted person: (A xor B) opens envelope -> master")

print(f"{fails} FAILED, {oks} passed" if fails else f"all {oks} checks passed")
sys.exit(1 if fails else 0)
