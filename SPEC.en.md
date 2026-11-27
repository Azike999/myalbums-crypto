# My Albums — how the encryption works

[Русский](SPEC.md) · as of 27 November 2026 · `crypto.js` SHA-256 `54ad03d1…ec7c7e1`

Everything below is taken from the code, not from memory. The formats are checked against `test_vectors.json` by two
independent programs (`tests/`). If the code and this text ever disagree, the code is right. Please tell us
(`SECURITY.md`).

## 1. In short

- Every user has a **master key**: 32 random bytes, created on the phone. It never reaches our server unencrypted.
- Photos, videos and everything about them (caption, date, place, people, file name) are encrypted on the phone with
  **AES-256-GCM** before upload. The server and the storage only ever receive ciphertext.
- Everything uses the browser's standard WebCrypto (`crypto.subtle`). There is no home-made cryptography, except a
  JavaScript SHA-256 used to compute duplicate tags of large files chunk by chunk (3.4). It gives the same result as
  WebCrypto, and the tests check that.
- What this does **not** guarantee is stated in section 10, "Limitations".

## 2. Keys

| Key | Origin | Protection / location |
|---|---|---|
| Master | 32 bytes from `crypto.getRandomValues` | See section 5. Never sent to the server in plaintext |
| Duplicate key | `SHA-256(master ‖ "dedup")` | Derived, not stored |
| File key | 32 random bytes per file | Inside the photo's metadata (`fk`), which is encrypted with the album key |
| Secret-album key | 32 random bytes | Wrapped with a password-derived key (PBKDF2), kept in the encrypted catalog. Deliberately **not** wrapped with the master key, so an unlocked phone alone does not open it |
| Shared-album key | 32 random bytes, independent of the master key | Owner: in the catalog. Members: ECIES to their public key (3.6). Link guests: PBKDF2 of the link code |
| User ECDH P-256 pair | `generateKey` | Public half on the server in plaintext. Private half on the server, encrypted with the master key |

The **recovery code** is the master key itself in base32 (RFC 4648 alphabet, no `=`): 52 characters in groups of 4.
On input it tolerates lower case, spaces, digits 0/1/8 instead of O/I/B, and look-alike Cyrillic letters
(`normB32` in `crypto.js`).

## 3. Algorithms and formats

### 3.1 Small objects: previews, thumbnails, photo metadata, catalog
AES-256-GCM with a random 12-byte IV. Output: `IV(12) ‖ ciphertext ‖ GCM tag(16)`. GCM authenticates the data. A wrong
key or a flipped byte is refused rather than decrypted into garbage, and that refusal is how the app detects a wrong
code or password.

### 3.2 Large files and video: the chunked format `PBC1`
The file is cut into 1 MiB chunks, each encrypted separately. Video can then be seeked without a full download, and
the phone never has to hold the whole file in memory.

```
header, 32 bytes: "PBC1" | chunk size u32 (1048576) | plaintext length u64 | 8 random bytes | 8 zero bytes
chunk i:          AES-256-GCM, IV = header's 8 random bytes ‖ u32(i), AAD = header ‖ u32(i)
file:             header ‖ chunk 0 ‖ chunk 1 ‖ …   (each chunk carries its own 16-byte tag)
```
Binding each chunk to the header and to its index in the AAD prevents reordering chunks, swapping in chunks from
another file, or silently truncating the file. `tests/check_vectors.mjs` checks this too.

### 3.3 File keys
Since 26 September 2026 every file has its own random key. The original, the 2048 px preview and the 400 px thumbnail
are encrypted with it. The file key is stored inside the photo's metadata, which is encrypted with the album key, so
moving a photo to another album re-encrypts only the metadata, not the file. Files uploaded before that date have no
file key and are encrypted with the album key.

### 3.4 Duplicate tag
`HMAC-SHA256(duplicate key, file bytes)`. The server compares tags to avoid storing the same file twice. In secret and
shared albums the tag is additionally passed through HMAC with the album's duplicate key (`albumTag`), so the server
cannot link a photo to its copy in another album. For large files the HMAC is computed chunk by chunk
(`dedupStream`, JavaScript SHA-256). The result equals the one-shot HMAC, and the tests check that.

### 3.5 Passwords: secret album, password-locked shared album, guest link code
`PBKDF2-HMAC-SHA256`, 300,000 iterations, 16-byte random salt, password normalised with NFKC. The 32-byte result is an
AES-GCM key that wraps the 32-byte album key (3.1). A guest link code is 80 random bits (16 base32 characters) and is
used the same way.

### 3.6 Sending a key to another person or device: ECIES `E1`
The sender's ephemeral ECDH P-256 key and the recipient's public key give a 256-bit shared secret. That goes through
`HKDF-SHA256` (16-byte random salt, info `"myalbums-shared-v1"`) to produce an AES-256-GCM key.
Serialised as `E1.<sender public key, 65 bytes>.<salt>.<IV>.<ciphertext>`, each part in base64.
It is used for a shared-album key sent to a member, the master key sent to a new device (6), and half A for the
trusted person (8).

### 3.7 Digits that detect public-key substitution
- **Shared-album safety code:** 10 digits from SHA-256 of the member's public key (about 33 bits). It is the same on
  both screens and is compared by voice.
- **Device link check:** 4 digits from SHA-256 of the new device's public key (sections 6 and 10).
- **Trusted-person code** (`heirCode`): 16 digits from the first 8 bytes of SHA-256 of the trusted person's public
  key (about 53 bits). The trusted person computes their code from **their own private** key (`pubFromPrivEnc`),
  not from the public key the server reports. Otherwise a dishonest server could show both people the same digits
  of a substituted key.

## 4. What is encrypted

Encrypted on the phone before upload:
- **Files:** original, 2048 px preview, 400 px thumbnail. For video, the poster frame is the preview.
- **Per-photo metadata**, as one encrypted record: file name, type, caption, capture date, coordinates, width and
  height, video duration, original size, album, people tags, face descriptors used for "who is this" suggestions,
  file key, content tag.
- **Catalog:** album names, covers, people's names, keys of secret and shared albums, content-search vectors.
- **Shared album:** name, cover, description and other album data, under the album key. Members' reactions (which
  emoji, on which photo) are also under the album key.

Face suggestions, content search, place names from coordinates (a built-in place list), HEIC decoding and video
posters are all computed on the phone. No map services or third-party geocoders are called.

## 5. Where the master key is stored

| Running as | Key location |
|---|---|
| Telegram Mini App | Telegram CloudStorage (bound to the Telegram account and our bot; the Bot API has no method to read it) **and** the device's `localStorage` |
| iPhone app | iOS Keychain (`AfterFirstUnlockThisDeviceOnly`, not synced to iCloud) and `localStorage` |
| Android app | Encrypted with an AndroidKeyStore key, kept in app preferences; Android backup disabled |
| Browser | `localStorage` |

The key is kept as plain base64 in CloudStorage and `localStorage`, because the page code reads it from there.
**Telegram can technically read the key from CloudStorage.** This is a deliberate trade-off: without it, the key would
be lost with the phone. See section 10.

The key reaches our server only in wrapped form:
- during a device link (section 6; ECIES to the new device's key);
- in the trusted-person envelope (section 8);
- the private ECDH half and the copies of shared-album keys, which are wrapped with the master key.

## 6. Moving the key to a new device

1. **Same Telegram account:** the key is found in CloudStorage automatically.
2. **Recovery code:** type or paste the 52 characters.
3. **Linking a device without Telegram** (the iPhone or Android app, or a browser):
   - the new device creates a one-time ECDH P-256 key pair and gives the server its public half;
   - the user approves the link in the Telegram Mini App, which already has the key. The Mini App wraps the master key
     to that public half (ECIES, 3.6) and gives the server only the wrapped key;
   - the new device collects it once (the request lives 10 minutes) and opens it with its private half;
   - both screens show the same 4 digits. If the server swapped the public key, the digits will most likely differ.
     The weakness of this check is described in section 10.

## 7. If the key is lost

There is no server-side recovery: we have no copy. Without the recovery code, the Telegram account with
CloudStorage, or a device that still has the key, the photos are lost. The app can create a new key, but old files
cannot be opened with it. Partial ways back:
- the **trusted person**, after the inactivity period (view only, secret albums excluded);
- **shared albums**, whose keys other members still hold.

A forgotten secret-album password cannot be recovered at all.

## 8. Trusted person ("two of two")

If the owner does not sign in for the chosen number of months, a person they chose gets view-only access.
The owner's phone (`heirSeal`):
- creates an envelope key E and a random half A, with B = E xor A;
- creates the envelope C = AES-GCM(E, master key);
- wraps A to the trusted person's public key (ECIES).

The server stores C, B and the wrapped A. The server lacks A. The trusted person lacks B until the deadline, when the
server releases it. The trusted person (`heirOpen`) opens A with their private key, computes E = A xor B, and opens C to
get the master key. Before sealing, the owner and the trusted person compare 16 digits (3.7) by phone or in person.
The owner's phone wraps half A only after "Codes match". Before 27 November 2026 sealing happened automatically,
without a comparison (section 10).

## 9. What the server sees in plaintext

Encryption hides content, not everything around it. The server knows:
- **account:** Telegram user id, name, username and language; time zone; platform (iPhone, Android, browser); plan and
  payments; where the user first came from;
- **activity:** which days the app was opened (first and last time), and names of steps taken (for example, "invited
  to a shared album");
- **files:** how many; the exact sizes of original, preview and thumbnail (from the ciphertext length); photo or
  video; upload time; duplicate tags. The server can tell when the same file is uploaded again, including the
  pre-upload check of files the user selected;
- **shared albums:** owner, members and roles, who joined via a link, which photo is in which shared album, who
  uploaded it, who reacted and when (not which reaction);
- **dates used for reminders:** the "Portrait of the year" day (month and day, often a birthday); the opening date of
  a time capsule; upcoming Saturdays that have "memories" from earlier years;
- **trusted person:** who trusts whom, the period, dates;
- **linked devices:** name ("Chrome · Windows"), platform, dates;
- **questions to the AI helper "Kadrik":** question and answer text. They are sent to an AI provider (Anthropic) and
  kept by us for up to 90 days, not linked to the account. Photos and captions are never sent, but any name or place
  typed into a question goes there in plaintext.

### When the server sees a file itself
Only on the user's own action, and only for their own file:
- **"To chat", "Send", and "Download" in Telegram on Android**, including collages and slideshow videos. Telegram's
  Android browser cannot save files, so the phone decrypts the file and hands it to the server. The server forwards it
  to Telegram or serves it through a one-time link. For "Download", the file stays on the server's disk for up to
  15 minutes, and the file name appears in the link and in the request log;
- **photos sent to the bot in a chat.** Telegram delivers them, so the server sees them like any bot message. Name,
  type, date and caption are kept in plaintext for up to 7 days, until the app picks the photo up. The photo itself
  passes through the server to the phone, which encrypts and uploads it as usual.

## 10. Limitations: what the code does not guarantee

1. **The page code comes from our server.** This is a web app. The iPhone and Android apps also load the page from
   the server rather than shipping it inside the app. A compromised or dishonest server could one day serve a modified
   `crypto.js` or `app.js` that sends the key away. No browser-based end-to-end encrypted service has fully solved
   this.
   - **What we do now.** The cryptography is published here and served byte for byte, and `verify.py` checks it. An
     hourly check run from outside our server compares everything the phone receives with the released version and
     raises an alert on any difference. The server also checks its own files every hour. The CSP stops the page from
     running third-party scripts (except Telegram's).
   - **What this does not cover.** Checking `crypto.js` alone does not prove that `app.js` will not send the key:
     `app.js` is not published and is served minified, and two small files (iPhone video streaming and best-shot
     selection) are obfuscated. Modified code could be served selectively to one person, and a general check would not
     see it. Telegram's own script (`telegram-web-app.js`) is loaded from Telegram's servers.
   - **What could close it.**
     - publish the SHA-256 of every released version here and in the changelog;
     - load `crypto.js` with `integrity="sha256-…"` (SRI);
     - ship `crypto.js` and hash checks inside the iPhone and Android apps, so they do not take crypto code from the
       server;
     - an independent audit.
2. **Telegram can read the master key** from CloudStorage, as can anyone who takes over the Telegram account. By
   default a guest link and its code are sent together in one Telegram message. A guest's album key is saved in the
   guest's CloudStorage.
3. **Key-substitution checks are short or optional.** These guard against a dishonest server that swaps public keys
   without changing any code:
   - **device link:** 4 digits. Finding a key pair with the same 4 digits takes about 10,000 tries, which is seconds;
   - **trusted person:** since 27 November 2026 the envelope is sealed only after comparing 16 digits (section 8).
     Envelopes sealed earlier were made without a comparison: a server holding B could have substituted its own key
     then. To be safe, the trusted person can be set up again;
   - **shared album:** the 10-digit safety code is shown, but comparing it is optional.
4. **Metadata is visible** (section 9): sizes, timing, the shared-album social graph, reminder dates.
5. **The recovery code is the key itself** (256 bits, no password). Whoever sees it has everything.
6. **An unlocked phone** with Telegram open opens the library. Secret albums require their password.
7. **A former shared-album member** keeps the file keys of photos they have already seen.
8. **Database backups** are kept for 31 days. They contain what is listed in section 9 and wrapped (not plaintext)
   copies of keys.

## 11. How to check

See `README.en.md`: `verify.py` checks that the served file is this one; `tests/check_vectors.mjs` and
`tests/check_vectors.py` check the formats.
