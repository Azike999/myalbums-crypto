# My Albums — encryption

[Русский](README.md)

My Albums stores photos and videos in Telegram (@MyAlbumsBot) and in apps for iPhone and Android.
Photos are encrypted on the phone **before** upload, and the server keeps only ciphertext. This repository
publishes the code that does it, so that you, or any specialist, can check that yourself instead of taking our word for it.

Only the encryption is published. The rest of the app and the server code are closed.

## Contents

| File | What it is |
|---|---|
| `crypto.js` | All of the app's cryptography. An exact, byte-for-byte copy of the file your phone receives |
| `SPEC.en.md` | Algorithms, where the key lives, what is encrypted, what the server sees in plaintext, limitations ([Русский](SPEC.md)) |
| `test_vectors.json` | Test vectors: known key and data → expected ciphertext |
| `tests/check_vectors.mjs` | Checks the vectors against the real `crypto.js` (Node.js 20+) |
| `tests/check_vectors.py` | Independent check in Python, written from the spec without `crypto.js` |
| `tests/make_vectors.mjs` | How the vectors were produced |
| `verify.py` | Downloads `crypto.js` from the app and compares it with the file here |
| `SECURITY.md` | How to report a vulnerability |

## Check it yourself

**1. Is it the same file your phone gets?** Python 3.8+ only:

```
python verify.py
```

The script downloads `https://app.myalbumsbot.com/static/crypto.js` and compares its SHA-256 with `crypto.js` here.
`SAME` means identical. `--beta` also checks the beta channel. The file is served unchanged (no minification).
The script disables transfer compression and compares exactly the bytes the browser executes. The app page loads
it as `crypto.js?v=<number>`; that is only a cache-busting tag, and the content is the same.

Without the script: open the app in Telegram Web in Chrome, press F12 → Sources → `static/crypto.js`, and compare.

**2. Does the code do what the spec says?**

```
node tests/check_vectors.mjs        # vectors against crypto.js itself
pip install cryptography
python tests/check_vectors.py       # independent implementation of the spec
```

Both must end with `all … checks passed`. The Python check does not use `crypto.js`. If it agrees with the vectors,
the formats in the spec are described correctly: AES-256-GCM, the chunked PBC1 format, PBKDF2, ECDH P-256 + HKDF, and the rest.

**3. What this repository does NOT prove.** Read "Limitations" in the spec. In short: the app page is served
by our server, and checking `crypto.js` alone does not rule out other page code sending the key somewhere. The spec
says what protects against that today and what could.

## Vulnerabilities

See `SECURITY.md`.

## License

Not chosen yet.
