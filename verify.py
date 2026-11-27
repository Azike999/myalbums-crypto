# -*- coding: utf-8 -*-
"""Compare the encryption files that the My Albums app really serves with the files in this repository:
crypto.js and lib/noble-p256.js (the P-256 library crypto.js loads, only with its SRI hash, when a device is linked).

    python verify.py                 # main channel
    python verify.py --beta          # beta channel too
    python verify.py --url <address> # any other address of crypto.js (the library is looked up next to it)

Only the Python standard library is used. Exit code 0 = identical, 1 = different, 2 = could not check.

Сверка: скачивает crypto.js и lib/noble-p256.js с публичного адреса приложения и сравнивает SHA-256 с файлами
в репозитории.
"""
import argparse
import base64
import hashlib
import os
import re
import sys
import urllib.request

APP = "https://app.myalbumsbot.com"
PATHS = {"main": "/static/crypto.js", "beta": "/static-beta/crypto.js"}
FILES = ("crypto.js", "lib/noble-p256.js")
HERE = os.path.dirname(os.path.abspath(__file__))


def fetch(url):
    # ask for the file without compression: we compare exactly the bytes the browser ends up executing
    req = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache",
                                               "User-Agent": "myalbums-crypto-verify/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        enc = (r.headers.get("Content-Encoding") or "identity").lower()
        if enc != "identity":
            raise RuntimeError(f"server answered with Content-Encoding: {enc} — cannot compare raw bytes")
        return r.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--beta", action="store_true", help="also check the beta channel")
    ap.add_argument("--url", help="check this address of crypto.js instead")
    a = ap.parse_args()
    local = {f: open(os.path.join(HERE, *f.split("/")), "rb").read() for f in FILES}
    for f in FILES:
        print(f"repository  {f:<18} sha256 {hashlib.sha256(local[f]).hexdigest()}  ({len(local[f])} bytes)")
    # crypto.js pins the library by its hash (Subresource Integrity): check that the pin matches the file here
    sri = "sha256-" + base64.b64encode(hashlib.sha256(local["lib/noble-p256.js"]).digest()).decode()
    pin = re.search(rb'LINK_LIB_SRI = "([^"]+)"', local["crypto.js"])
    pinned = pin and pin.group(1).decode() == sri
    print(f"{'SAME     ' if pinned else 'DIFFERENT'}  SRI hash written in crypto.js = hash of lib/noble-p256.js  ({sri})")
    code = 0 if pinned else 1
    bases = [a.url.rsplit("/", 1)[0] + "/"] if a.url else \
        [APP + PATHS["main"].rsplit("/", 1)[0] + "/"] + ([APP + PATHS["beta"].rsplit("/", 1)[0] + "/"] if a.beta else [])
    for base in bases:
        for f in FILES:
            url = a.url if (a.url and f == "crypto.js") else base + f
            try:
                got = fetch(url)
            except Exception as e:                       # noqa: BLE001 — any network problem = "could not check"
                print(f"COULD NOT CHECK  {url}: {e}")
                code = max(code, 2)
                continue
            h = hashlib.sha256(got).hexdigest()
            same = got == local[f]
            print(f"{'SAME     ' if same else 'DIFFERENT'}  {url}  sha256 {h}  ({len(got)} bytes)")
            if not same:
                code = 1
                if got.replace(b"\r\n", b"\n") == local[f].replace(b"\r\n", b"\n"):
                    print("           (differs only in line endings CRLF/LF)")
    if code == 1:
        print("A served file is not the published one. If the repository is older than the app, compare with "
              "the newest commit; otherwise please report it — see SECURITY.md.")
    return code


if __name__ == "__main__":
    sys.exit(main())
