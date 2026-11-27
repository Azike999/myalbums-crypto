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

d = E["device_link"]
dpriv = serialization.load_der_private_key(b64(d["device_priv_pkcs8_b64"]), None)
ok(ecies_open(d["wrapped"], dpriv) == master, "device link: master key unwrapped by new device")
h = hashlib.sha256(b64(d["device_pub_spki_b64"])).digest()
ok(str(int.from_bytes(h[:3], "big") % 10000).zfill(4) == d["link_check"], "device link: 4-digit check")

he = E["heir"]
hpriv = serialization.load_der_private_key(b64(he["heir_priv_pkcs8_b64"]), None)
A = ecies_open(he["share_a_enc"], hpriv)
B = b64(he["share_b"])
Ekey = bytes(x ^ y for x, y in zip(A, B))
ok(dec(Ekey, b64(he["env"])) == master, "trusted person: (A xor B) opens envelope -> master")

print(f"{fails} FAILED, {oks} passed" if fails else f"all {oks} checks passed")
sys.exit(1 if fails else 0)
