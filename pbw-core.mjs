// Private Box Web — NUCLEO MVP (formati e crittografia), replica esatta della
// specifica v0.9. Questo file NON va modificato dall'agente: è la fonte di
// verità, dimostrata dai test in test-core.mjs contro vectors_v09.json.
// Dipendenze: libsodium-wrappers-sumo (serve la variante sumo per crypto_pwhash/Argon2id)
// + WebCrypto (browser in https o Node 18+).

import _sodium from "libsodium-wrappers-sumo";

export let sodium = null;
export async function init() {
  await _sodium.ready;
  sodium = _sodium;
  return sodium;
}

// ---------- costanti del formato (identiche al generatore) ----------
export const VER = 1;
export const FORMAT_HKDF_SALT = te("private-box/hkdf-salt/v1");
export const INFO_OBJ = te("private-box/obj-wrap/v1");
export const INFO_CRED = te("private-box/cred-auth/v1");
export const INFO_KIT = "private-box/kit-kek/v1";
export const D_PW = "private-box/ad/cred-pw/v1";
export const D_KIT = "private-box/ad/cred-kit/v1";
export const D_OBJ = "private-box/ad/obj-key/v1";
export const ROOT_ID = "0".repeat(26);
export const CODEC_ID = "pbw-num-v1";
export const CHUNK = 1_048_576;
export const HDR_MAX = 65_536;
export const OPS_MIN = 2, OPS_MAX_LEGGIBILE = 32, OPS_MAX_TENTABILE = 6;
export const MEM_MIN = 64 * 1024 * 1024, MEM_MAX_LEGGIBILE = 1024 * 1024 * 1024;
export const MEM_MAX_TENTABILE = 256 * 1024 * 1024;  // tetto memoria per non bloccare il browser
export const PW_MAX = 1024, PW_MIN_PUNTI = 8;
export const INT_MAX = Number.MAX_SAFE_INTEGER; // 2^53 - 1
export const HDR_CAND_MAX = 40;
export const MVP_FILE_MAX = 100 * 1024 * 1024;
export const BLOCKLIST_V1 = ["123456","12345678","123456789","1234567890","password",
  "password1","password123","qwerty","qwertyuiop","111111","123123","000000","abc123",
  "iloveyou","admin","welcome","monkey","dragon","letmein","sunshine","princess","football",
  "baseball","master","superman","batman","trustno1","ciaociao","juventus","napoli",
  "francesca","qwerty123"];

function te(s) { return new TextEncoder().encode(s); }
function td(b) { return new TextDecoder("utf-8", { fatal: true }).decode(b); }
export function concat(...arrs) {
  const n = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(n); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
export function eq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ---------- JCS (sottoinsieme: chiavi ordinate, niente spazi, solo interi) ----------
export function jcs(obj) { return te(jcsStr(obj)); }
export function jcsStr(x) {
  if (x === null || typeof x === "boolean") throw new Error("JCS: tipo non ammesso");
  if (typeof x === "number") {
    if (!Number.isInteger(x) || Math.abs(x) > INT_MAX) throw new Error("JCS: solo interi entro 2^53-1");
    return String(x);
  }
  if (typeof x === "string") return JSON.stringify(x);
  if (Array.isArray(x)) return "[" + x.map(jcsStr).join(",") + "]";
  const keys = Object.keys(x).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + jcsStr(x[k])).join(",") + "}";
}
export function parseStrictJson(bytes) {
  const s = td(bytes);
  let dup = false;
  const obj = JSON.parse(s, function (k, v) {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      // JSON.parse non segnala i duplicati: il confronto JCS sotto li intercetta
    }
    if (v === null) dup = true;
    return v;
  });
  if (dup) throw new Error("intestazione con null");
  if (jcsStr(obj) !== s) throw new Error("intestazione non in forma JCS");
  return obj;
}

// ---------- codifiche ----------
const B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
export function b64u(b) {
  let out = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    out += B64C[(n >> 18) & 63] + B64C[(n >> 12) & 63]
        + (i + 1 < b.length ? B64C[(n >> 6) & 63] : "")
        + (i + 2 < b.length ? B64C[n & 63] : "");
  }
  return out;
}
export function b64uDec(s) {
  if (typeof s !== "string" || /[^A-Za-z0-9\-_]/.test(s)) throw new Error("base64url non valido");
  if (s.length % 4 === 1) throw new Error("base64url di lunghezza impossibile");
  const out = new Uint8Array(Math.floor(s.length * 3 / 4));
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    let n = 0, c = 0;
    for (let j = 0; j < 4 && i + j < s.length; j++) { n = (n << 6) | B64C.indexOf(s[i + j]); c++; }
    n <<= 6 * (4 - c);
    if (c > 1) out[o++] = (n >> 16) & 255;
    if (c > 2) out[o++] = (n >> 8) & 255;
    if (c > 3) out[o++] = n & 255;
  }
  const res = out.subarray(0, o);
  if (b64u(res) !== s) throw new Error("base64url non canonico"); // bit di padding non-zero, alias
  return res;
}

export const ALPHA = "0123456789abcdefghjkmnpqrstvwxyz";
export function b32Enc16(b16) {
  if (b16.length !== 16) throw new Error("id: servono 16 byte");
  let v = 0n; for (const x of b16) v = (v << 8n) | BigInt(x);
  v <<= 2n;
  let out = "";
  for (let i = 25; i >= 0; i--) out += ALPHA[Number((v >> (5n * BigInt(i))) & 31n)];
  return out;
}
export function b32Dec16(s) {
  if (s.length !== 26 || [...s].some(c => !ALPHA.includes(c)))
    throw new Error("id non canonico: lunghezza o alfabeto");
  let v = 0n; for (const c of s) v = (v << 5n) | BigInt(ALPHA.indexOf(c));
  if (v & 3n) throw new Error("id non canonico: bit di padding non a zero");
  v >>= 2n;
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) { out[i] = Number(v & 255n); v >>= 8n; }
  return out;
}
// NORMATIVO (S1 della v0.9): gruppi da 5 bit dal più significativo, padding IN CODA
export function b32OfDigest(b) {
  const nbits = b.length * 8, nch = Math.ceil(nbits / 5);
  let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x);
  v <<= BigInt(nch * 5 - nbits);
  let out = "";
  for (let i = nch - 1; i >= 0; i--) out += ALPHA[Number((v >> (5n * BigInt(i))) & 31n)];
  return out;
}

// ---------- primitive ----------
export function blake32(b) { return sodium.crypto_generichash(32, b); }
export function randomBytes(n) { return sodium.randombytes_buf(n); }
export function newId16() { return b32Enc16(randomBytes(16)); }

// HMAC standard costruito su SHA-256/SHA-512 di libsodium: byte-identico a WebCrypto,
// ma senza dipendere da crypto.subtle (che richiede un "contesto sicuro"). Cosi' il
// tool offline funziona anche aperto da disco (file://).
function rawHash(algo, x) { return algo === "SHA-256" ? sodium.crypto_hash_sha256(x) : sodium.crypto_hash_sha512(x); }
async function hmac(algo, key, msg) {
  const block = algo === "SHA-256" ? 64 : 128;
  let k = key; if (k.length > block) k = rawHash(algo, k);
  const kb = new Uint8Array(block); kb.set(k);
  const ipad = new Uint8Array(block), opad = new Uint8Array(block);
  for (let i = 0; i < block; i++) { ipad[i] = kb[i] ^ 0x36; opad[i] = kb[i] ^ 0x5c; }
  return rawHash(algo, concat(opad, rawHash(algo, concat(ipad, msg))));
}
export async function hkdfSha256(ikm, salt, info, ln = 32) {
  const prk = await hmac("SHA-256", salt, ikm);
  let out = new Uint8Array(0), t = new Uint8Array(0), i = 1;
  while (out.length < ln) {
    t = await hmac("SHA-256", prk, concat(t, info, new Uint8Array([i])));
    out = concat(out, t); i++;
  }
  return out.subarray(0, ln);
}
export async function credAuth(kCred, msg) {         // crypto_auth = HMAC-SHA-512-256
  return (await hmac("SHA-512", kCred, msg)).subarray(0, 32);
}
export async function sha256(b) { return sodium.crypto_hash_sha256(b); }

export async function deriveSubkeys(vaultKey) {
  return { kObj: await hkdfSha256(vaultKey, FORMAT_HKDF_SALT, INFO_OBJ),
           kCred: await hkdfSha256(vaultKey, FORMAT_HKDF_SALT, INFO_CRED) };
}
export function kekFromPassword(pwBytes, salt, ops, mem) {
  return sodium.crypto_pwhash(32, pwBytes, salt, ops, mem,
                              sodium.crypto_pwhash_ALG_ARGON2ID13);
}
export async function kekFromKit(kitSecret, kitSalt) {
  return hkdfSha256(kitSecret, kitSalt, te(INFO_KIT));
}

// ---------- password: buona formazione, minimo, blocklist ----------
function pwEncode(pwStr) {                            // R06: tetto lunghezza prima di elaborare
  if (typeof pwStr !== "string" || pwStr.length > 4096) throw new Error("password non valida o troppo lunga");
  for (let i = 0; i < pwStr.length; i++) {
    const c = pwStr.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = pwStr.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) throw new Error("surrogate non appaiata: password non ben formata");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new Error("surrogate non appaiata: password non ben formata");
    }
  }
  const b = te(pwStr);
  if (b.length < 1 || b.length > PW_MAX) throw new Error("password fuori dai limiti di codifica");
  return b;
}
export function passwordBytes(pwStr) {                // in CREAZIONE: impone anche il minimo 8
  const b = pwEncode(pwStr);
  if ([...pwStr].length < PW_MIN_PUNTI) throw new Error("password troppo corta: minimo 8 caratteri");
  return b;
}
export function passwordBytesForUnlock(pwStr) {       // R07: in APERTURA solo buona formazione + max
  return pwEncode(pwStr);
}
export function checkBlocklist(pwStr, lista) {
  const norm = pwStr.normalize("NFKC").toLowerCase();        // F08/N06: confronto normalizzato
  if (lista.some(x => x.normalize("NFKC").toLowerCase() === norm))
    throw new Error("password troppo comune (pbw-blocklist-v1)");
}
export function generateProposal20() {               // rejection sampling normativo
  let out = "";
  while (out.length < 20) {
    for (const b of randomBytes(32)) {
      if (b < 250) { out += String(b % 10); if (out.length === 20) break; }
    }
  }
  return out;
}

// ---------- codec del Kit (pbw-num-v1) ----------
export async function kitEncode(secret16) {
  let v = 0n; for (const x of secret16) v = (v << 8n) | BigInt(x);
  const payload = v.toString().padStart(40, "0");
  const h = await sha256(secret16);
  const chk = String(((h[0] << 8) | h[1]) % 10000).padStart(4, "0");
  const code = payload + chk;
  return Array.from({ length: 11 }, (_, i) => code.slice(i * 4, i * 4 + 4)).join("-");
}
export async function kitDecode(text) {
  if (typeof text !== "string" || text.length > 256) throw new Error("Kit troppo lungo"); // R06
  let digits = "";
  for (const ch of text) {
    if (ch === " " || ch === "-" || ch === "\u00a0") continue;
    if (ch < "0" || ch > "9") throw new Error("carattere non ammesso");
    digits += ch;
  }
  if (digits.length < 44) throw new Error("troppo corto");
  if (digits.length > 44) throw new Error("troppo lungo");
  const num = BigInt(digits.slice(0, 40));
  if (num >= (1n << 128n)) throw new Error("payload fuori intervallo");
  const secret = new Uint8Array(16);
  let v = num; for (let i = 15; i >= 0; i--) { secret[i] = Number(v & 255n); v >>= 8n; }
  const h = await sha256(secret);
  if (String(((h[0] << 8) | h[1]) % 10000).padStart(4, "0") !== digits.slice(40))
    throw new Error("checksum errato");
  return secret;
}

// ---------- AD canonici ----------
export function adPw(vid, ops, mem, salt) {
  return jcs({ d: D_PW, v: 1, vault_id: vid, alg: "ARGON2ID13", ops, mem, salt: b64u(salt) });
}
export function adKit(vid, codec, kitSalt) {
  return jcs({ d: D_KIT, v: 1, vault_id: vid, codec_id: codec, salt: b64u(kitSalt),
               kdf: "HKDF-SHA256", info: INFO_KIT });
}
export function adObj(vid, ftype, ident) {
  return jcs({ d: D_OBJ, v: 1, vault_id: vid, file_type: ftype, id: ident });
}

// ---------- framing dei file ----------
export function buildFile(magic, headerObj, body) {
  const h = jcs(headerObj);
  if (h.length > HDR_MAX) throw new Error("intestazione oltre il tetto");
  const head = new Uint8Array(9);
  head.set(te(magic), 0);
  head[4] = 0; head[5] = VER;
  head[6] = (h.length >> 16) & 255; head[7] = (h.length >> 8) & 255; head[8] = h.length & 255;
  return concat(head, h, body ?? new Uint8Array(0));
}
export function parseFile(raw, magic) {
  if (raw.length < 9) throw new Error("file troncato");
  if (td(raw.subarray(0, 4)) !== magic) throw new Error("magic");
  if (((raw[4] << 8) | raw[5]) !== VER) throw new Error("versione");
  const hl = (raw[6] << 16) | (raw[7] << 8) | raw[8];
  if (hl > HDR_MAX) throw new Error("intestazione oltre il tetto");
  if (raw.length < 9 + hl) throw new Error("intestazione troncata");
  const obj = parseStrictJson(raw.subarray(9, 9 + hl));
  return [obj, raw.subarray(9 + hl)];
}

// ---------- secretstream: framing dei record ----------
export function frames(body) {
  const SS_A = sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
  const BODY_MAX = MVP_FILE_MAX + 4 * 1024 * 1024;              // tetto fisico con margine
  const MAX_RECORDS = Math.ceil(MVP_FILE_MAX / CHUNK) + 8;      // ~110 per 100MB
  if (body.length > BODY_MAX) throw new Error("corpo del file oltre il tetto fisico");
  const out = []; let i = 0;
  while (i < body.length) {
    if (i + 4 > body.length) throw new Error("framing troncato");
    const ln = (body[i] * 16777216) + (body[i + 1] << 16) + (body[i + 2] << 8) + body[i + 3];
    if (ln < SS_A) throw new Error("record piu corto del minimo crittografico");   // F06: no frame bomb
    if (ln > CHUNK + SS_A) throw new Error("record oltre il tetto di pre-allocazione");
    i += 4;
    if (i + ln > body.length) throw new Error("record troncato");
    out.push(body.subarray(i, i + ln)); i += ln;
    if (out.length > MAX_RECORDS) throw new Error("troppi record nel corpo");       // F06: tetto numero
  }
  return out;
}
export function ssEncrypt(key, plainRecords) {       // [[bytes, tag], ...]
  const st = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const parts = [];
  for (const [pt, tag] of plainRecords) {
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(st.state, pt, null, tag);
    const ln = new Uint8Array(4);
    ln[0] = (ct.length >>> 24) & 255; ln[1] = (ct.length >>> 16) & 255;
    ln[2] = (ct.length >>> 8) & 255; ln[3] = ct.length & 255;
    parts.push(ln, ct);
  }
  return { ssHeader: st.header, body: concat(...parts) };
}
export function ssDecrypt(key, ssHeader, body) {
  const TAG_FIN = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
  const st = sodium.crypto_secretstream_xchacha20poly1305_init_pull(ssHeader, key);
  const out = []; let fin = false;
  for (const ct of frames(body)) {
    if (fin) throw new Error("byte residui dopo TAG_FINAL");
    const r = sodium.crypto_secretstream_xchacha20poly1305_pull(st, ct, null);
    if (!r) throw new Error("record non decifrabile");
    out.push([r.message, r.tag]); fin = (r.tag === TAG_FIN);
  }
  if (!fin) throw new Error("manca TAG_FINAL");
  return out;
}

// ---------- intestazione PBH1 ----------
export async function makeHeader(o) {
  // o: {vaultId, vaultKey, kCred, rev, kekPw, saltPw, noncePw, ops, mem,
  //     kitSalt, nonceKit, kekKit (oppure wrapKitFixed), created}
  const aPw = adPw(o.vaultId, o.ops, o.mem, o.saltPw);
  const aKit = adKit(o.vaultId, CODEC_ID, o.kitSalt);
  const wPw = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(o.vaultKey, aPw, null, o.noncePw, o.kekPw);
  const wKit = o.wrapKitFixed ??
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(o.vaultKey, aKit, null, o.nonceKit, o.kekKit);
  const h = { v: 1, vault_id: o.vaultId, header_revision: o.rev,
    migration: { state: "none" },
    kdf_pw: { alg: "ARGON2ID13", ops: o.ops, mem: o.mem, salt: b64u(o.saltPw) },
    kit: { codec_id: CODEC_ID, salt: b64u(o.kitSalt), kdf: "HKDF-SHA256", info: INFO_KIT },
    wrap_pw: { nonce: b64u(o.noncePw), ct: b64u(wPw) },
    wrap_kit: { nonce: b64u(o.nonceKit), ct: b64u(wKit) },
    created: o.created };
  h.cred_auth = b64u(await credAuth(o.kCred, jcs(h)));
  return buildFile("PBH1", h, new Uint8Array(0));
}
export function validateKdf(k) {
  if (k.alg !== "ARGON2ID13") throw new Error("kdf non supportata");
  if (!(Number.isInteger(k.ops) && k.ops >= OPS_MIN && k.ops <= OPS_MAX_LEGGIBILE))
    throw new Error("parametri kdf fuori dai limiti leggibili");
  if (!(Number.isInteger(k.mem) && k.mem >= MEM_MIN && k.mem <= MEM_MAX_LEGGIBILE))
    throw new Error("parametri kdf fuori dai limiti leggibili");
  return k.ops <= OPS_MAX_TENTABILE && k.mem <= MEM_MAX_TENTABILE; // F01: tempo E memoria
}
export async function headerAuth(raw, kCred) {
  const [h, body] = parseFile(raw, "PBH1");
  if (body.length !== 0) throw new Error("PBH1 con corpo");
  validateKdf(h.kdf_pw);
  const { cred_auth, ...h2 } = h;
  const tag = b64uDec(cred_auth);
  if (!eq(tag, await credAuth(kCred, jcs(h2)))) throw new Error("cred_auth non valido");
  return h;
}
export function tryOpenPw(h, kek) {
  const a = adPw(h.vault_id, h.kdf_pw.ops, h.kdf_pw.mem, b64uDec(h.kdf_pw.salt));
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, b64uDec(h.wrap_pw.ct), a, b64uDec(h.wrap_pw.nonce), kek);
}
export function openKitWrap(h, kekKit) {
  const a = adKit(h.vault_id, h.kit.codec_id, b64uDec(h.kit.salt));
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, b64uDec(h.wrap_kit.ct), a, b64uDec(h.wrap_kit.nonce), kekKit);
}

// ---------- oggetti cifrati (PBM1, PBO1) ----------
export function wrappedObject(magic, ftype, ident, objKey, nonce, records, idField, kObj, vaultId) {
  const { ssHeader, body } = ssEncrypt(objKey, records);
  const w = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(objKey, adObj(vaultId, ftype, ident), null, nonce, kObj);
  const h = { v: 1, vault_id: vaultId,
              obj_key_wrap: { nonce: b64u(nonce), ct: b64u(w) },
              ss_header: b64u(ssHeader) };
  h[idField] = ident;
  return buildFile(magic, h, body);
}
export function openObject(raw, magic, ftype, idField, expectedName, kObj) {
  const [h, body] = parseFile(raw, magic);
  const ident = h[idField];
  b32Dec16(ident);
  if (expectedName != null && expectedName !== ident)
    throw new Error("nome fisico e id interno non coincidono");
  const ok = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, b64uDec(h.obj_key_wrap.ct), adObj(h.vault_id, ftype, ident),
    b64uDec(h.obj_key_wrap.nonce), kObj);
  return { header: h, records: ssDecrypt(ok, b64uDec(h.ss_header), body) };
}

export function metaSchemaCheck(p) {
  if (p.stato === "eliminato" && "content_id" in p) throw new Error("content_id vietato nello stato eliminato");
  if ((p.stato === "attivo" || p.stato === "cestinato") && p.tipo === "file" && !("content_id" in p))
    throw new Error("content_id obbligatorio per file attivo o cestinato");
  const rev = p.revisione ?? 1;
  if (rev >= 2 && !("prev_meta_digest" in p)) throw new Error("prev_meta_digest obbligatorio dalla revisione 2");
  if (rev === 1 && "prev_meta_digest" in p) throw new Error("prev_meta_digest vietato alla revisione 1");
  if (!(rev >= 1 && rev <= INT_MAX)) throw new Error("revisione fuori intervallo 1..2^53-1");
}

export function makeMeta(payload, kObj, vaultId) {
  metaSchemaCheck(payload);
  const TAG_FIN = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
  return wrappedObject("PBM1", "meta", payload.entry_id, randomBytes(32), randomBytes(24),
                       [[jcs(payload), TAG_FIN]], "entry_id", kObj, vaultId);
}
export function openMeta(raw, expectedName, kObj) {
  const { records } = openObject(raw, "PBM1", "meta", "entry_id", expectedName, kObj);
  if (records.length !== 1) throw new Error("PBM1: atteso un solo record");
  const p = parseStrictJson(records[0][0]);
  metaSchemaCheck(p);
  return p;
}

export function makeContent(contentId, contentBytes, nomeOriginale, created, opId, kObj, vaultId) {
  if (contentBytes.length > MVP_FILE_MAX) throw new Error("file oltre il limite MVP di 100 MB");
  const TAG_MSG = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
  const TAG_FIN = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
  const payload = { nome_originale: nomeOriginale, dimensione_originale: contentBytes.length,
                    blake2b256_contenuto: b64u(blake32(contentBytes)), creato: created, op_id: opId };
  const recs = [];
  if (contentBytes.length === 0) {
    recs.push([jcs(payload), TAG_FIN]);
  } else {
    recs.push([jcs(payload), TAG_MSG]);
    for (let i = 0; i < contentBytes.length; i += CHUNK) {
      const chunk = contentBytes.subarray(i, Math.min(i + CHUNK, contentBytes.length));
      recs.push([chunk, i + CHUNK >= contentBytes.length ? TAG_FIN : TAG_MSG]);
    }
  }
  return wrappedObject("PBO1", "content", contentId, randomBytes(32), randomBytes(24),
                       recs, "content_id", kObj, vaultId);
}
export function openContent(raw, expectedName, kObj) {
  const { records } = openObject(raw, "PBO1", "content", "content_id", expectedName, kObj);
  const payload = parseStrictJson(records[0][0]);
  const content = records.length > 1 ? concat(...records.slice(1).map(r => r[0])) : new Uint8Array(0);
  if (content.length !== payload.dimensione_originale) throw new Error("quadratura: dimensione non corrispondente");
  if (b64u(blake32(content)) !== payload.blake2b256_contenuto) throw new Error("quadratura: impronta non corrispondente");
  return { payload, content };
}

// ---------- selezione MVP delle intestazioni (sez. 8.1 ridotta allo scope) ----------
// candidates: [{name, bytes}] · kekForParams: async (saltB, ops, mem) => kek
// Esiti onesti (rilievi 7, 14, 15 dell'ottavo giro): radice mista rifiutata,
// "password errata" solo dopo aver provato TUTTE le intestazioni tentabili,
// parametri non tentabili => indeterminato, mai conclusioni non provate.
export async function selectHeadersMvp(candidates, kekForParams) {
  if (candidates.length > HDR_CAND_MAX)
    throw new Error("troppe intestazioni candidate: pulizia guidata necessaria");
  const gruppi = new Map(); const scarti = [];
  for (const c of candidates) {
    try {
      const [h] = parseFile(c.bytes, "PBH1");
      if (!gruppi.has(h.vault_id)) gruppi.set(h.vault_id, []);
      gruppi.get(h.vault_id).push({ ...c, h });
    } catch (e) { scarti.push({ name: c.name, err: String(e.message ?? e) }); }
  }
  if (gruppi.size === 0) throw new Error("nessuna intestazione leggibile: recupero guidato");
  if (gruppi.size > 1)
    throw new Error("radice mista: questa cartella contiene più di una cassaforte; separale prima di procedere");
  const [vaultId, cands] = [...gruppi.entries()][0];
  let nonTentabili = 0; const tentati = []; const keks = new Map();
  for (const c of cands) {
    let tentabile;
    try { tentabile = validateKdf(c.h.kdf_pw); }
    catch (e) { scarti.push({ name: c.name, err: String(e.message ?? e) }); continue; }
    if (!tentabile) { nonTentabili++; continue; }
    const kk = c.h.kdf_pw.salt + "|" + c.h.kdf_pw.ops + "|" + c.h.kdf_pw.mem;
    if (!keks.has(kk))
      keks.set(kk, await kekForParams(b64uDec(c.h.kdf_pw.salt), c.h.kdf_pw.ops, c.h.kdf_pw.mem));
    tentati.push({ ...c, kek: keks.get(kk) });
  }
  if (tentati.length === 0)
    throw new Error("nessuna intestazione tentabile su questa macchina: esito indeterminato");
  let best = null;
  for (const c of tentati) {
    try {
      const vk = tryOpenPw(c.h, c.kek);
      if (!best || c.h.header_revision > best.h.header_revision) best = { ...c, vaultKey: vk };
    } catch { /* questa non si apre con questa password */ }
  }
  const maxRev = Math.max(...cands.map(c => c.h.header_revision ?? 0));
  if (!best) {
    if (nonTentabili > 0)
      throw new Error("credenziale non verificabile su tutte le copie: esito indeterminato");
    throw new Error("password errata: nessuna intestazione si apre");
  }
  if (best.h.header_revision < maxRev)
    throw new Error("password revocata: apre solo una revisione inferiore alla massima");
  const { kObj, kCred } = await deriveSubkeys(best.vaultKey);
  const verified = [];
  for (const c of cands) {
    try { await headerAuth(c.bytes, kCred); verified.push(c.name); }
    catch (e) { scarti.push({ name: c.name, err: String(e.message ?? e) }); }
  }
  if (!verified.includes(best.name)) throw new Error("cred_auth non valido sull'intestazione aperta");
  return { vaultId, vaultKey: best.vaultKey, kObj, kCred, header: best.h,
           revision: best.h.header_revision, verified, scarti,
           avviso: scarti.length ? "file di intestazione inattesi o non validi presenti (in sola quarantena logica)" : null };
}
