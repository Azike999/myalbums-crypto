/* © 2026 My Albums (ИП «Азия+», Астана). Все права защищены. Официально: @MyAlbumsBot, myalbumsbot.com */
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
    /* ---- вход с устройства без Телеграма (12.11.2026, app/devices.py). Новое устройство создаёт разовую пару и
       отдаёт открытую половину; устройство с ключом (мини-приложение в Телеграме) запирает для неё основной ключ той
       же обёрткой ECIES, что у общих альбомов; сервер носит только запертое. linkCheck — 4 цифры от открытой
       половины: одинаковы на обоих экранах, если сервер половину не подменил. */
    linkPair: async () => {
      const kp = await subtle.generateKey(ECDH, true, ["deriveBits"]);
      return { pub: b64enc(await subtle.exportKey("spki", kp.publicKey)), priv: b64enc(await subtle.exportKey("pkcs8", kp.privateKey)) };
    },
    linkWrap: (pubB64) => eciesWrap(master.raw, pubB64),
    linkOpen: async (wrapped, privB64) => {
      const raw = await eciesUnwrap(wrapped, await subtle.importKey("pkcs8", b64dec(privB64), ECDH, false, ["deriveBits"]));
      if (raw.length !== 32) throw new Error("ключ не той длины");
      return b64enc(raw);
    },
    linkCheck: async (pubB64) => {
      const h = new Uint8Array(await subtle.digest("SHA-256", b64dec(pubB64)));
      return String(((h[0] << 16) | (h[1] << 8) | h[2]) % 10000).padStart(4, "0");
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
