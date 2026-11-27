# lib/noble-p256.js — how it was built

`crypto.js` needs elliptic-curve point addition for SPAKE2 (SPEC.md, 3.8), which WebCrypto does not offer. It takes
the P-256 point type from [@noble/curves](https://github.com/paulmillr/noble-curves) (MIT, audited; see its README,
"Security"). Nothing else from the library is used. License: `noble-p256.LICENSE.txt`.

Exact packages from the npm registry (registry signatures and provenance attestations verified with
`npm audit signatures`): `@noble/curves@2.4.0`, `@noble/hashes@2.4.0`, bundled with `esbuild@0.28.2`.

```
npm install --ignore-scripts --save-exact @noble/curves@2.4.0 @noble/hashes@2.4.0 esbuild@0.28.2
# entry.mjs:
#   import { p256 } from '@noble/curves/nist.js';
#   export const Point = p256.Point;
npx esbuild entry.mjs --bundle --format=iife --global-name=nobleP256 --target=es2020 --legal-comments=inline \
  --charset=utf8 --banner:js="/* @noble/curves 2.4.0 + @noble/hashes 2.4.0 (MIT, https://github.com/paulmillr/noble-curves) - only the P-256 point (nobleP256.Point). Built by esbuild 0.28.2, see lib/BUILD.md in myalbums-crypto. */" \
  --outfile=noble-p256.js
```

Expected SHA-256 of the result: `c4e83fca5085bebe6dd26cb61ec38974b6cbb60bc356ac665802374acf99be1f`.
The file is not minified, so it can be read. The same hash, in base64, is written in `crypto.js` as `LINK_LIB_SRI`.
