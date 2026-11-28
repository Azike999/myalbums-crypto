/* © 2026 My Albums (ИП «Азия+», Астана). Этот файл — под лицензией MIT (открытый репозиторий myalbums-crypto).
   Официально: @MyAlbumsBot, myalbumsbot.com */
/* Шифрование на телефоне. Сервер видит только результат работы этого файла.

   Основной ключ: 32 случайных байта (AES-256). Живёт в CloudStorage Telegram
   (привязан к аккаунту пользователя, наш сервер туда не ходит) и в
   localStorage как кэш. Человеку показывается как КОД ВОССТАНОВЛЕНИЯ —
   52 символа base32 группами по 4.

   Секретный альбом (v0.4): свой ключ альбома, 32 случайных байта. Он
   «завёрнут» ключом из пароля (PBKDF2-SHA256, 300 000 итераций, соль 16 байт)
   и лежит в каталоге. Основным ключом альбомный НЕ заворачиваем нарочно:
   иначе любой, у кого в руках разблокированный телефон, открыл бы альбом
   без пароля. Пароль забыт — альбом потерян, восстановить нельзя.

   Файлы и метаданные: AES-GCM, случайный IV 12 байт, выход = IV || шифротекст.
   GCM заодно проверяет целостность: чужой ключ не «расшифрует в мусор»,
   а честно откажет — так приложение узнаёт, что код или пароль неверный.

   Дубликаты: HMAC-SHA256(ключ_дубликатов, байты файла). Сервер сравнивает
   метки, но содержимое из них не вытащить. Ключ дубликатов = SHA-256(ключ || "dedup"),
   для секретного альбома — от его ключа, чтобы перенос между альбомами не
   считался дубликатом. */
window.PBCrypto = (function () {
  const subtle = crypto.subtle;
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const PBKDF2_ITER = 300000;
  const ECDH = { name: "ECDH", namedCurve: "P-256" };      // пара ключей для общих альбомов (выше return — иначе не успеет присвоиться)

  function b32enc(bytes) {
    let bits = 0, val = 0, out = "";
    for (const b of bytes) {
      val = (val << 8) | b; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    return out;
  }
  /* Набранный руками код → алфавит base32. Порядок важен (03.10.2026): раньше «лишние» знаки
     вычищались ДО замены 0→O и 1→I — набранные цифры 0/1 просто исчезали и код «неполный».
     Кириллица: на русской раскладке А В Е К М Н О Р С Т Х выглядят как латинские — человек
     переписывает код с бумаги и не видит разницы. 8 путают с B — как в коде приглашения. */
  const LOOK = { "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X" };
  const normB32 = (str) => String(str || "").toUpperCase().replace(/[АВЕКМНОРСТХ]/g, (c) => LOOK[c])
    .replace(/0/g, "O").replace(/1/g, "I").replace(/8/g, "B").replace(/[^A-Z2-7]/g, "");
  function b32dec(str) {
    const s = normB32(str);
    let bits = 0, val = 0; const out = [];
    for (const ch of s) {
      const v = B32.indexOf(ch); if (v < 0) return null;
      val = (val << 5) | v; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }
  const b64enc = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const b64dec = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  // Пара ключей из сырых байт: AES для данных, HMAC для меток дубликатов
  async function keyPair(raw) {
    const aes = await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    const seed = new Uint8Array([...raw, ...new TextEncoder().encode("dedup")]);
    const h = await subtle.digest("SHA-256", seed);
    const hmac = await subtle.importKey("raw", h, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return { raw, aes, hmac, hk: new Uint8Array(h) };      // hk — тот же ключ HMAC байтами: метка большого файла считается по кускам
  }

  let master = null;                 // {raw, aes, hmac}

  async function encWith(k, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, k.aes, bytes);
    const out = new Uint8Array(12 + ct.byteLength); out.set(iv); out.set(new Uint8Array(ct), 12);
    return out;
  }
  async function decWith(k, bytes) {
    const u = new Uint8Array(bytes);
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: u.slice(0, 12) }, k.aes, u.slice(12)));
  }

  /* ---- Шифрование кусками (19.09.2026) — для видео и больших файлов.
     Раньше файл шифровался одним куском: чтобы его отправить, телефон держал в памяти ~3 размера видео
     (Android из-за этого выгружал галерею, и остальные файлы пачки переставали читаться), а чтобы
     посмотреть — скачивал и расшифровывал целиком. Теперь файл = заголовок 32 байта + куски по 1 МиБ,
     каждый зашифрован AES-GCM отдельно: можно шифровать, читая файл с диска частями, и расшифровать
     любой кусок по номеру — видео играет и перематывается без полной загрузки.
     Заголовок: «PBC1» | размер куска u32 | длина открытого файла u64 | 8 случайных байт | 8 нулей.
     IV куска i = 8 случайных байт заголовка + u32(i); дополнительные данные (AAD) = заголовок + u32(i):
     кусок нельзя переставить, подменить кусками другого файла или незаметно обрезать файл. */
  const CH = 1048576, CH_HDR = 32, CH_TAG = 16, CH_MAGIC = [0x50, 0x42, 0x43, 0x31];
  function chunkHeader(total) {
    const h = new Uint8Array(CH_HDR), v = new DataView(h.buffer); h.set(CH_MAGIC);
    v.setUint32(4, CH); v.setUint32(8, Math.floor(total / 4294967296)); v.setUint32(12, total >>> 0);
    h.set(crypto.getRandomValues(new Uint8Array(8)), 16); return h;
  }
  /* Разбор заголовка: {chunk, total, n, size, hdr} или null. fileLen (если известна) должна сойтись
     точно — старый формат начинается со случайного IV и за кусочный принят не будет. */
  function parseChunked(bytes, fileLen) {
    const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (u.length < CH_HDR || CH_MAGIC.some((b, i) => u[i] !== b)) return null;
    for (let i = 24; i < 32; i++) if (u[i]) return null;
    const v = new DataView(u.buffer, u.byteOffset, CH_HDR), chunk = v.getUint32(4), total = v.getUint32(8) * 4294967296 + v.getUint32(12);
    if (chunk < 65536 || chunk > 16777216 || (chunk & (chunk - 1))) return null;
    const n = Math.max(1, Math.ceil(total / chunk)), size = CH_HDR + total + n * CH_TAG;
    if (fileLen != null && fileLen !== size) return null;
    return { chunk, total, n, size, hdr: u.slice(0, CH_HDR) };
  }
  const chunkIv = (hdr, i) => { const iv = new Uint8Array(12); iv.set(hdr.subarray(16, 24)); new DataView(iv.buffer).setUint32(8, i); return iv; };
  const chunkAad = (hdr, i) => { const a = new Uint8Array(CH_HDR + 4); a.set(hdr); new DataView(a.buffer).setUint32(CH_HDR, i); return a; };
  const encChunk = async (k, hdr, i, bytes) => new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: chunkIv(hdr, i), additionalData: chunkAad(hdr, i) }, k.aes, bytes));
  const decChunk = async (k, hdr, i, bytes) => new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: chunkIv(hdr, i), additionalData: chunkAad(hdr, i) }, k.aes, bytes));
  // где лежит кусок i в зашифрованном файле: [from, to)
  const chunkSpan = (info, i) => { const from = CH_HDR + i * (info.chunk + CH_TAG), plain = Math.min(info.chunk, info.total - i * info.chunk); return [from, from + Math.max(0, plain) + CH_TAG]; };
  /* Файл с диска → Blob шифротекста, не читая файл целиком. onChunk(открытый кусок, №, всего) — для метки и хода. */
  async function encryptFileChunked(file, k, onChunk) {
    const total = file.size, hdr = chunkHeader(total), n = Math.max(1, Math.ceil(total / CH)), parts = [hdr];
    for (let i = 0; i < n; i++) {
      const plain = new Uint8Array(await file.slice(i * CH, Math.min(total, (i + 1) * CH)).arrayBuffer());
      if (onChunk) await onChunk(plain, i, n);
      parts.push(await encChunk(k, hdr, i, plain));
    }
    return new Blob(parts);
  }
  /* То же, но шифротекст не собирается в Blob, а отдаётся по мере готовности: onCipher(байты) — заголовок, потом
     куски по порядку. Загрузка частями (22.09.2026): видео в 2–4 ГБ телефон не удержит в памяти целиком. */
  async function encryptFileStream(file, k, onPlain, onCipher) {
    const total = file.size, hdr = chunkHeader(total), n = Math.max(1, Math.ceil(total / CH));
    await onCipher(hdr);
    for (let i = 0; i < n; i++) {
      const plain = new Uint8Array(await file.slice(i * CH, Math.min(total, (i + 1) * CH)).arrayBuffer());
      if (onPlain) await onPlain(plain, i, n);
      await onCipher(await encChunk(k, hdr, i, plain));
    }
  }
  async function decryptChunkedAll(u, k, info) {
    const out = new Uint8Array(info.total);
    for (let i = 0; i < info.n; i++) { const [a, b] = chunkSpan(info, i); out.set(await decChunk(k, info.hdr, i, u.subarray(a, b)), i * info.chunk); }
    return out;
  }
  // единая расшифровка: сама узнаёт кусочный формат (перенос в секретный альбом, «Оригинал», дата из файла)
  async function decAuto(k, bytes) {
    const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), info = parseChunked(u, u.length);
    return info ? decryptChunkedAll(u, k, info) : decWith(k, u);
  }

  /* SHA-256 и HMAC по частям: WebCrypto умеет только «всё сразу», а метка дубликата большого файла
     должна совпадать с прежней (HMAC-SHA256 от всего содержимого) — иначе уже загруженные видео
     перестали бы узнаваться как дубликаты. */
  const SHA_K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function Sha256() {
    const h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]), w = new Uint32Array(64), buf = new Uint8Array(64);
    let bl = 0, len = 0;
    const block = (p, o) => {
      for (let i = 0; i < 16; i++, o += 4) w[i] = (p[o] << 24) | (p[o + 1] << 16) | (p[o + 2] << 8) | p[o + 3];
      for (let i = 16; i < 64; i++) { const a = w[i - 15], b = w[i - 2]; w[i] = (w[i - 16] + (((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)) + w[i - 7] + (((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10))) | 0; }
      let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (let i = 0; i < 64; i++) {
        const t1 = (hh + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
        const t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    };
    const update = (p) => {
      let o = 0; len += p.length;
      if (bl) { const take = Math.min(64 - bl, p.length); buf.set(p.subarray(0, take), bl); bl += take; o = take; if (bl === 64) { block(buf, 0); bl = 0; } }
      for (; o + 64 <= p.length; o += 64) block(p, o);
      if (o < p.length) { buf.set(p.subarray(o), bl); bl += p.length - o; }
    };
    const digest = () => {
      const bits = len * 8, pad = new Uint8Array(((bl + 9 + 63) & ~63) - bl); pad[0] = 0x80;
      const v = new DataView(pad.buffer); v.setUint32(pad.length - 8, Math.floor(bits / 4294967296)); v.setUint32(pad.length - 4, bits >>> 0);
      update(pad);
      const out = new Uint8Array(32), ov = new DataView(out.buffer); for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i]); return out;
    };
    return { update, digest };
  }
  function hmacStream(keyBytes) {
    const k = new Uint8Array(64); k.set(keyBytes);                       // ключ 32 байта — короче блока, хешировать его не нужно
    const inner = Sha256(), ipad = k.map(b => b ^ 0x36), opad = k.map(b => b ^ 0x5c); inner.update(ipad);
    return { update: (p) => inner.update(p), digest() { const o = Sha256(); o.update(opad); o.update(inner.digest()); return o.digest(); } };
  }

  /* Доверенный человек (02.11.2026, app/heir.py) — те же ECIES-обёртки, что у общих альбомов, но над сырыми байтами. */
  async function eciesWrap(raw, pubB64) {
    const pub = await subtle.importKey("spki", b64dec(pubB64), ECDH, false, []);
    const eph = await subtle.generateKey(ECDH, true, ["deriveBits"]);
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await eciesKey(eph.privateKey, pub, salt);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, k, raw));
    return "E1." + [new Uint8Array(await subtle.exportKey("raw", eph.publicKey)), salt, iv, ct].map(b64enc).join(".");
  }
  async function eciesUnwrap(wrapped, priv) {
    const [v, e, s, i, c] = String(wrapped).split(".");
    if (v !== "E1") throw new Error("не тот формат ключа");
    const k = await eciesKey(priv, await subtle.importKey("raw", b64dec(e), ECDH, false, []), b64dec(s));
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: b64dec(i) }, k, b64dec(c)));
  }

  /* ---- Подключение устройства по коду (27.11.2026, владелец: вариант «Б»). Раньше Телеграм запирал основной ключ
     на открытую половину нового устройства, а человек сверял 4 цифры от неё. Сервер, подменивший половину, подбирал
     пару с теми же цифрами за секунды, а любую короткую сверку можно подобрать заранее.
     Теперь — SPAKE2 по RFC 9382 (набор P256-SHA256-HKDF-HMAC, стандартные точки M и N). Новое устройство (сторона A)
     показывает 6 случайных цифр. Они не уходят ни на сервер, ни в Телеграм: человек сам набирает их в Телеграме
     (сторона B). Обе стороны вмешивают код в обмен ключами, и общий ключ Ke совпадает, только если код один и тот же.
     Сервер, подменивший сообщения, может лишь угадывать: одна попытка на один ввод кода, шанс 1 из миллиона, и неудача
     видна человеку («код не подошёл»). Подобрать заранее нечего: из пересланных данных код не вычислить.
     Отступление от RFC: подтверждение cA от A к B не посылается — B сразу отвечает cB и основным ключом, запертым
     ключом из Ke. Иначе Телеграм пришлось бы держать открытым до ответа нового устройства (на одном телефоне —
     4 переключения вместо 2). Попыток угадать это не добавляет: каждый ответ B — одна попытка, как и в RFC.
     Сложения точек кривой в WebCrypto нет, поэтому P-256 — из библиотеки @noble/curves (MIT, проверена независимыми
     аудиторами): lib/noble-p256.js. Грузится только при подключении и только с этим отпечатком (SRI) — подменить её,
     не поменяв этот файл, нельзя. */
  const LINK_LIB = "lib/noble-p256.js", LINK_LIB_SRI = "sha256-xOg/ylCFvr5t0my2HsOJdLbLtgvDVqxmWAI3Ss+Zvh8=";
  const LINK_IDS = ["myalbums-link-v1:device", "myalbums-link-v1:telegram"];        // A и B в стенограмме RFC
  const SPAKE_M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";   // RFC 9382, §6, P-256
  const SPAKE_N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
  let p256load = null;
  function p256() {
    if (globalThis.nobleP256) return Promise.resolve(globalThis.nobleP256.Point);
    if (!p256load) p256load = new Promise((res, rej) => {
      const s0 = document.querySelector('script[src*="crypto.js"]'), sc = document.createElement("script");
      sc.src = (s0 ? s0.src.replace(/crypto\.js.*$/, "") : "/static/") + LINK_LIB;
      sc.integrity = LINK_LIB_SRI;                                  // браузер сверит отпечаток и не выполнит чужой файл
      sc.onload = () => (globalThis.nobleP256 ? res(globalThis.nobleP256.Point) : rej(new Error("p256")));
      sc.onerror = () => rej(new Error("p256"));
      document.head.appendChild(sc);
    }).catch((e) => { p256load = null; throw e; });
    return p256load;
  }
  const utf8 = (str) => new TextEncoder().encode(str);
  const hex2b = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
  const b2hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const b2n = (b) => BigInt("0x" + (b2hex(b) || "0"));
  const n2b = (n) => hex2b(n.toString(16).padStart(64, "0"));           // w в стенограмме — 32 байта, старшие вперёд
  function cat(...parts) {
    const o = new Uint8Array(parts.reduce((t, p) => t + p.length, 0)); let i = 0;
    for (const p of parts) { o.set(p, i); i += p.length; }
    return o;
  }
  const lenp = (b) => { const l = new Uint8Array(8); new DataView(l.buffer).setUint32(0, b.length, true); return cat(l, b); };   // len(x) || x, длина — 8 байт little-endian
  const digest = async (alg, b) => new Uint8Array(await subtle.digest(alg, b));
  async function hkdf(ikm, info, len) {
    const k = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info }, k, len * 8));
  }
  async function hmac(key, msg) {
    const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("HMAC", k, msg));
  }
  // 6 цифр → w: SHA-512 (на 64+ бита длиннее порядка кривой — без перекоса, как советует RFC) по модулю порядка n
  async function spakeW(code, n) {
    const d = String(code || "").replace(/\D/g, "");
    if (d.length !== 6) throw new Error("link_code");
    return b2n(await digest("SHA-512", utf8("myalbums-link-v1:w:" + d))) % n;
  }
  function spakeScalar(n) {             // равномерно из [1, n): выпавшее за край отбрасываем (RFC: rejection sampling)
    for (;;) { const v = b2n(crypto.getRandomValues(new Uint8Array(32))); if (v > 0n && v < n) return v; }
  }
  // одна сторона SPAKE2: своё сообщение, а если пришло сообщение собеседника — ключи по RFC 9382, §3.3 и §4
  async function spake(P, role, ids, w, s, peer) {
    const M = P.fromHex(SPAKE_M), N = P.fromHex(SPAKE_N), [mine, theirs] = role === "A" ? [M, N] : [N, M];
    const msg = P.BASE.multiply(s).add(mine.multiply(w)).toBytes(false);
    if (!peer) return { msg };
    const pt = P.fromBytes(peer); pt.assertValidity();                 // RFC §7: точка собеседника — только с кривой
    const K = pt.subtract(theirs.multiply(w)).multiply(s).toBytes(false);   // кофактор P-256 = 1
    const [pA, pB] = role === "A" ? [msg, peer] : [peer, msg];
    const TT = cat(lenp(utf8(ids[0])), lenp(utf8(ids[1])), lenp(pA), lenp(pB), lenp(K), lenp(n2b(w)));
    const h = await digest("SHA-256", TT), Ke = h.slice(0, 16), Ka = h.slice(16);
    const kc = await hkdf(Ka, utf8("ConfirmationKeys"), 32), KcA = kc.slice(0, 16), KcB = kc.slice(16);
    return { msg, pA, pB, K, TT, Ke, Ka, KcA, KcB, cA: await hmac(KcA, TT), cB: await hmac(KcB, TT) };
  }
  // ключ, которым B запирает основной ключ: HKDF от Ke со своей меткой (сам Ke никуда не идёт)
  const linkBox = async (Ke) => ({ aes: await subtle.importKey("raw", await hkdf(Ke, utf8("myalbums-link-v1:master"), 32), "AES-GCM", false, ["encrypt", "decrypt"]) });
  const sameBytes = (a, b) => a.length === b.length && a.reduce((d, x, i) => d | (x ^ b[i]), 0) === 0;

  return {
    hasKey: () => !!master,
    /* ---- доверенный человек: конверт «два из двух». E — ключ конверта, A и B — половины (B = E xor A):
       конверт C = основной ключ, запертый E; A — заперта для доверенного (его открытая половина), B — остаётся серверу.
       Ни сервер (нет A), ни доверенный до срока (нет B) ключ не соберут. */
    heirSeal: async (heirPubB64) => {
      const E = crypto.getRandomValues(new Uint8Array(32)), A = crypto.getRandomValues(new Uint8Array(32));
      const B = E.map((x, i) => x ^ A[i]);
      return { env: b64enc(await encWith(await keyPair(E), master.raw)), share_b: b64enc(B), share_a_enc: await eciesWrap(A, heirPubB64) };
    },
    // доверенный: A — своей закрытой половиной, B — от сервера → E → основной ключ хозяина (base64, для load)
    heirOpen: async (env, shareB64, shareAEnc, priv) => {
      const A = await eciesUnwrap(shareAEnc, priv), B = b64dec(shareB64);
      if (A.length !== 32 || B.length !== 32) throw new Error("половины не сходятся");
      const E = A.map((x, i) => x ^ B[i]);
      return b64enc(await decWith(await keyPair(E), b64dec(env)));
    },
    generate: async () => { master = await keyPair(crypto.getRandomValues(new Uint8Array(32))); },
    load: async (b64) => { master = await keyPair(b64dec(b64)); },
    exportB64: () => b64enc(master.raw),
    recoveryCode: () => b32enc(master.raw).match(/.{1,4}/g).join("-"),
    fromRecoveryCode: async (code) => {
      const k = b32dec(code);
      if (!k || k.length < 32) throw new Error("код неполный");
      master = await keyPair(k.slice(0, 32));
    },

    // k — ключ (объект из keyPair) или null = основной
    encryptBytes: (bytes, k) => encWith(k || master, bytes),
    decryptBytes: (bytes, k) => decAuto(k || master, bytes),          // понимает и старый формат, и кусочный
    encryptJSON: async (obj, k) => b64enc(await encWith(k || master, new TextEncoder().encode(JSON.stringify(obj)))),
    decryptJSON: async (b64, k) => JSON.parse(new TextDecoder().decode(await decWith(k || master, b64dec(b64)))),
    dedupTag: async (bytes, k) => b64enc(await subtle.sign("HMAC", (k || master).hmac, bytes)),
    // ---- кусочный формат
    CHUNK: CH, CHUNK_HDR: CH_HDR, parseChunked, chunkSpan,
    encryptFileChunked: (file, k, onChunk) => encryptFileChunked(file, k || master, onChunk),
    encryptFileStream: (file, k, onPlain, onCipher) => encryptFileStream(file, k || master, onPlain, onCipher),
    chunkedSize: (total) => CH_HDR + total + Math.max(1, Math.ceil(total / CH)) * CH_TAG,   // размер шифротекста заранее
    encryptBytesChunked: async (bytes, k) => new Uint8Array(await (await encryptFileChunked(new Blob([bytes]), k || master)).arrayBuffer()),
    decryptChunk: (info, i, bytes, k) => decChunk(k || master, info.hdr, i, bytes),
    aesKey: (k) => (k || master).aes,                                  // для передачи в service worker (ключ неизвлекаемый)
    dedupStream: (k) => { const h = hmacStream((k || master).hk); return { update: (p) => h.update(p), digestB64: () => b64enc(h.digest()) }; },

    // ---- секретный альбом
    // создать: возвращает {salt, wrapped} для каталога и сам ключ для работы
    newAlbumKey: async (password) => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const kek = await keyPair(await pbkdf2(password, salt));
      return { salt: b64enc(salt), wrapped: b64enc(await encWith(kek, raw)), key: await keyPair(raw) };
    },
    // открыть: неверный пароль → исключение от GCM
    unlockAlbumKey: async (password, salt, wrapped) => {
      const kek = await keyPair(await pbkdf2(password, b64dec(salt)));
      return keyPair(await decWith(kek, b64dec(wrapped)));
    },
    // сменить пароль: тот же ключ альбома, новая обёртка
    rewrapAlbumKey: async (albumKey, password) => {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const kek = await keyPair(await pbkdf2(password, salt));
      return { salt: b64enc(salt), wrapped: b64enc(await encWith(kek, albumKey.raw)) };
    },
    /* ---- блокировка приложения (28.11.2026, владелец: «Делай» — код и Face ID / отпечаток на вход).
       Код из 6 цифр → PBKDF2-SHA256 (те же 300 000 итераций, соль 16 байт; к коду приписано «myalbums-lock-v1:», чтобы
       он никогда не совпал с паролем секретного альбома). Из результата: ver = SHA-256(«myalbums-lock-v1:ver» ‖ биты) —
       проверка кода в обычном режиме, и ключ-обёртка kek — в усиленном: основной ключ на устройстве и в облаке Телеграма
       лежит только запертым этим ключом (AES-GCM), неверный код честно отказывает. Отпечаток/Face ID: Телеграм хранит
       на телефоне случайный токен 32 байта и отдаёт его только после проверки; из токена — вторая обёртка ключа (только
       на этом устройстве). ЧЕСТНО: 6 цифр — 10⁶ вариантов; кто вынет из памяти телефона запертый ключ, переберёт их на
       своём компьютере. Усиленный режим защищает от того, кто просто взял телефон, а не от разбора памяти. */
    lockDerive: async (pin, saltB64) => {
      const salt = saltB64 ? b64dec(saltB64) : crypto.getRandomValues(new Uint8Array(16));
      const bits = await pbkdf2("myalbums-lock-v1:" + pin, salt);
      const ver = b64enc(await digest("SHA-256", cat(utf8("myalbums-lock-v1:ver"), bits)));
      return { salt: b64enc(salt), ver, kek: await keyPair(bits) };
    },
    lockSeal: async (kek) => b64enc(await encWith(kek, master.raw)),
    lockUnseal: async (kek, b64) => { master = await keyPair(await decWith(kek, b64dec(b64))); },
    lockToken: () => b64enc(crypto.getRandomValues(new Uint8Array(32))),
    tokenKek: async (tokenB64) => keyPair(b64dec(tokenB64)),
    /* Отпечаток основного ключа — для «Забыли код?» в усиленном режиме, когда ключа в памяти нет: код восстановления
       сверяется с ним, иначе чужой код снял бы блокировку и записал чужой ключ (стенд sim_lock, 28.11.2026). SHA-256 от
       случайных 32 байт с меткой: ключ по нему не восстановить. code не задан — отпечаток открытого ключа. */
    lockMk: async (code) => {
      const raw = code ? b32dec(code) : master.raw;
      if (!raw || raw.length < 32) throw new Error("код неполный");
      return b64enc(await digest("SHA-256", cat(utf8("myalbums-lock-v1:mk"), raw.slice(0, 32))));
    },
    // «Забыли код?» в обычном режиме: введённый код восстановления — тот же, что у открытого ключа (тогда блокировку снимаем)
    sameMaster: async (code) => { const raw = b32dec(code); return !!(raw && master && raw.length >= 32 && sameBytes(raw.slice(0, 32), master.raw)); },
    /* ---- ключ файла (26.09.2026, docs/security/FILE_KEYS.md). Раньше файлы шифровались ключом альбома, и чтобы
       сделать альбом общим или перенести фото в секретный, телефон скачивал, перешифровывал и заново отправлял
       каждый файл (владелец: «на 900 фотографий ушло 2 часа»). Теперь у каждого файла свой случайный ключ, а сам
       ключ лежит в сведениях фото (meta.fk), которые и так зашифрованы ключом альбома. Перенос в другой альбом —
       перешифровать только сведения: несколько сотен байт вместо файла. */
    newFileKey: async () => { const raw = crypto.getRandomValues(new Uint8Array(32)); return { raw: b64enc(raw), key: await keyPair(raw) }; },
    fileKey: async (rawB64) => keyPair(b64dec(rawB64)),
    /* Метка содержимого (meta.hc) = прежняя метка обычного альбома: HMAC(ключ дубликатов основного ключа, байты).
       Метка дубликата для сервера — от неё и ключа альбома, поэтому при переносе её можно пересчитать, не читая файл.
       Обычный альбом (k = null): метка = h — ровно как раньше, дубликаты среди старых фото узнаются.
       Секретный или общий: HMAC(ключ дубликатов альбома, h) — сервер не свяжет фото с его копией в другом альбоме. */
    albumTag: async (hB64, k) => k ? b64enc(await subtle.sign("HMAC", k.hmac, b64dec(hB64))) : hB64,
    /* ---- общий альбом (21.09.2026, docs/общие_альбомы_схема.md). Ключ случайный и НЕ зависит от основного:
       отдать гостю можно только его. У владельца он лежит в каталоге (каталог зашифрован основным ключом);
       гостю по ссылке уходит запертым КОДОМ — той же обёрткой, что пароль секретного альбома. */
    newSharedKey: async () => { const raw = crypto.getRandomValues(new Uint8Array(32)); return { raw: b64enc(raw), key: await keyPair(raw) }; },
    sharedKey: async (rawB64) => keyPair(b64dec(rawB64)),
    wrapSharedKey: async (key) => b64enc(await encWith(master, key.raw)),
    shareCode: () => b32enc(crypto.getRandomValues(new Uint8Array(10))).match(/.{1,4}/g).join("-"),   // 80 бит — 16 знаков
    rawB64: (key) => b64enc(key.raw),
    /* Код из приглашения: человек может набрать его строчными, без дефисов, спутать 0/O и 1/I —
       ключ запирается и отпирается одной и той же нормальной формой. */
    normShareCode: (s) => normB32(s),     // та же нормальная форма, что у кода восстановления (+ кириллица, 03.10.2026)
    recoveryLen: (s) => normB32(s).length,   // сколько знаков кода распознано — подсказать, если пропущена группа
    // ---- пара ключей человека для общих альбомов
    newUserPair: async () => {
      const kp = await subtle.generateKey(ECDH, true, ["deriveBits"]);
      const priv = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
      return { pub: b64enc(await subtle.exportKey("spki", kp.publicKey)), priv_enc: b64enc(await encWith(master, priv)),
               priv: await subtle.importKey("pkcs8", priv, ECDH, false, ["deriveBits"]) };
    },
    openUserPriv: async (privEnc) => subtle.importKey("pkcs8", await decWith(master, b64dec(privEnc)), ECDH, false, ["deriveBits"]),
    wrapForMember: async (albumKey, pubB64) => {
      const pub = await subtle.importKey("spki", b64dec(pubB64), ECDH, false, []);
      const eph = await subtle.generateKey(ECDH, true, ["deriveBits"]);
      const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
      const k = await eciesKey(eph.privateKey, pub, salt);
      const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, k, albumKey.raw));
      return "E1." + [new Uint8Array(await subtle.exportKey("raw", eph.publicKey)), salt, iv, ct].map(b64enc).join(".");
    },
    unwrapForMe: async (wrapped, priv) => {
      const [v, e, s, i, c] = String(wrapped).split(".");
      if (v !== "E1") throw new Error("не тот формат ключа");
      const k = await eciesKey(priv, await subtle.importKey("raw", b64dec(e), ECDH, false, []), b64dec(s));
      return keyPair(new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: b64dec(i) }, k, b64dec(c))));
    },
    // код безопасности: одинаков на экранах владельца и участника; сверяют голосом, если сомневаются
    safetyCode: async (pubB64) => {
      const h = new Uint8Array(await subtle.digest("SHA-256", b64dec(pubB64)));
      const n = (((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0) * 3 + (h[4] % 3);
      return String(n % 1e10).padStart(10, "0").replace(/(\d{5})(\d{5})/, "$1 $2");
    },
    /* ---- вход с устройства без Телеграма (12.11.2026, app/devices.py), с 27.11.2026 — по коду (SPAKE2, см. выше).
       A — новое устройство: linkCode → linkStart (сообщение серверу) → … → linkFinish (основной ключ).
       B — Телеграм с ключом: человек набирает 6 цифр → linkAnswer (ответ + основной ключ, запертый общим ключом).
       Сервер носит только сообщения SPAKE2 и запертое; ни кода, ни ключа у него нет. */
    linkCode: () => {
      for (;;) { const v = crypto.getRandomValues(new Uint32Array(1))[0]; if (v < 4294000000) return String(v % 1000000).padStart(6, "0"); }
    },
    linkStart: async (code) => {
      const P = await p256(), n = P.Fn.ORDER, w = await spakeW(code, n), x = spakeScalar(n);
      const { msg } = await spake(P, "A", LINK_IDS, w, x);
      return { msg: "S1." + b64enc(msg), state: { code: String(code), x: x.toString(16) } };   // state — до ответа B (переживает перезагрузку)
    },
    linkAnswer: async (code, msgA) => {
      const [v, a] = String(msgA || "").split(".");
      if (v !== "S1" || !a) throw new Error("link_old");                 // запрос старой страницы (4 цифры) — не отвечаем
      const P = await p256(), n = P.Fn.ORDER, w = await spakeW(code, n);
      const r = await spake(P, "B", LINK_IDS, w, spakeScalar(n), b64dec(a));
      return "S1." + [r.msg, r.cB, await encWith(await linkBox(r.Ke), master.raw)].map(b64enc).join(".");
    },
    linkFinish: async (state, answer) => {
      const [v, b, c, box] = String(answer || "").split(".");
      if (v !== "S1" || !b || !c || !box) throw new Error("link_bad");
      const P = await p256(), n = P.Fn.ORDER, w = await spakeW(state.code, n);
      const r = await spake(P, "A", LINK_IDS, w, BigInt("0x" + state.x), b64dec(b));
      if (!sameBytes(r.cB, b64dec(c))) throw new Error("link_code");     // набрали не тот код — или сообщения подменены
      const raw = await decWith(await linkBox(r.Ke), b64dec(box));
      if (raw.length !== 32) throw new Error("link_bad");
      return b64enc(raw);
    },
    // только для проверки по RFC 9382, приложение B: w, x, y заданы → все промежуточные значения (hex)
    spake2Vector: async (A, B, wHex, xHex, yHex) => {
      const P = await p256(), w = BigInt("0x" + wHex), x = BigInt("0x" + xHex);
      const pA = (await spake(P, "A", [A, B], w, x)).msg, b = await spake(P, "B", [A, B], w, BigInt("0x" + yHex), pA);
      const a = await spake(P, "A", [A, B], w, x, b.msg), o = {};
      for (const k of ["pA", "pB", "K", "TT", "Ke", "Ka", "KcA", "KcB", "cA", "cB"]) o[k] = b2hex(a[k]);
      o.bothSides = b2hex(b.Ke) === o.Ke && b2hex(b.cA) === o.cA;
      return o;
    },
    /* ---- сверка ключа доверенного (27.11.2026). Раньше телефон хозяина запирал половину A на открытую половину
       доверенного, взятую с сервера, без проверки: сервер, у которого и так половина B, мог подставить свою пару и собрать
       ключ. Теперь хозяин запечатывает конверт, только когда 16 цифр на его экране совпали с цифрами у доверенного
       (сверяют голосом). 16 цифр ≈ 53 бита: подобрать пару ECDH с теми же цифрами — порядка 10^16 попыток.
       Свою открытую половину доверенный выводит из СВОЕЙ закрытой (она заперта его основным ключом), а не берёт
       со слов сервера: иначе сервер показал бы обоим одну и ту же чужую половину. */
    heirCode: async (pubB64) => {
      const h = new Uint8Array(await subtle.digest("SHA-256", b64dec(pubB64)));
      let n = 0n; for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(h[i]);
      return String(n % 10000000000000000n).padStart(16, "0").replace(/(\d{4})(?=\d)/g, "$1 ");
    },
    pubFromPrivEnc: async (privEnc) => {
      const pk = await subtle.importKey("pkcs8", await decWith(master, b64dec(privEnc)), ECDH, true, ["deriveBits"]);
      const j = await subtle.exportKey("jwk", pk);
      const pub = await subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: j.x, y: j.y }, ECDH, true, []);
      return b64enc(await subtle.exportKey("spki", pub));
    },
    b32dec, b32enc,
  };

  /* Ключ альбома для участника — схема ECIES: разовая пара владельца + открытая половина участника (ECDH P-256)
     → HKDF → AES-GCM. Прочитать может только тот, у кого закрытая половина, а она заперта его основным ключом. */
  async function eciesKey(priv, pub, salt) {
    const bits = await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
    const hk = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("myalbums-shared-v1") },
                            hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function pbkdf2(password, salt) {
    const base = await subtle.importKey("raw", new TextEncoder().encode(password.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER }, base, 256));
  }
})();
