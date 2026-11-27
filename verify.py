# -*- coding: utf-8 -*-
"""Compare the crypto.js that the My Albums app really serves with crypto.js in this repository.

    python verify.py                 # main channel
    python verify.py --beta          # beta channel too
    python verify.py --url <address> # any other address of the file

Only the Python standard library is used. Exit code 0 = identical, 1 = different, 2 = could not check.

Сверка: скачивает crypto.js с публичного адреса приложения и сравнивает SHA-256 с файлом в репозитории.
"""
import argparse
import hashlib
import os
import sys
import urllib.request

APP = "https://app.myalbumsbot.com"
PATHS = {"main": "/static/crypto.js", "beta": "/static-beta/crypto.js"}
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
    ap.add_argument("--url", help="check this address instead")
    a = ap.parse_args()
    local = open(os.path.join(HERE, "crypto.js"), "rb").read()
    want = hashlib.sha256(local).hexdigest()
    print(f"repository  crypto.js  sha256 {want}  ({len(local)} bytes)")
    urls = [a.url] if a.url else [APP + PATHS["main"]] + ([APP + PATHS["beta"]] if a.beta else [])
    code = 0
    for url in urls:
        try:
            got = fetch(url)
        except Exception as e:                       # noqa: BLE001 — any network problem = "could not check"
            print(f"COULD NOT CHECK  {url}: {e}")
            code = max(code, 2)
            continue
        h = hashlib.sha256(got).hexdigest()
        same = h == want
        print(f"{'SAME     ' if same else 'DIFFERENT'}  {url}  sha256 {h}  ({len(got)} bytes)")
        if not same:
            code = 1
            if got.replace(b"\r\n", b"\n") == local.replace(b"\r\n", b"\n"):
                print("           (differs only in line endings CRLF/LF)")
    if code == 1:
        print("The served file is not the published one. If the repository is older than the app, compare with "
              "the newest commit; otherwise please report it — see SECURITY.md.")
    return code


if __name__ == "__main__":
    sys.exit(main())
