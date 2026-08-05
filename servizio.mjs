// Lockit · servizio.mjs — modulo del PRODOTTO (piano di cablaggio v0.4)
// parseStructural: passi 0b..12, MAI crittografia. autentica: SOLO passo 14.
// buildService: i byte normativi del servizio, firma completa (C4, H1).
import * as C from "./pbw-core.mjs";
import sodium from "libsodium-wrappers-sumo";
const te = (s) => new TextEncoder().encode(s);
const SIZE_MAX = 16 * 1024;              // tetto del file di servizio
export const HDR_BUDGET = 9 + C.HDR_MAX; // budget di lettura per file (G1)

// parseStructural è PURO: niente sodium qui dentro (la crittografia
// inizia col coordinatore delle derivazioni e con autentica).
const A64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function b64uEncPure(b) {
  let out = "", i = 0;
  for (; i + 3 <= b.length; i += 3) { const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out += A64[n >> 18] + A64[(n >> 12) & 63] + A64[(n >> 6) & 63] + A64[n & 63]; }
  const r = b.length - i;
  if (r === 1) { const n = b[i] << 16; out += A64[n >> 18] + A64[(n >> 12) & 63]; }
  else if (r === 2) { const n = (b[i] << 16) | (b[i + 1] << 8);
    out += A64[n >> 18] + A64[(n >> 12) & 63] + A64[(n >> 6) & 63]; }
  return out;
}
function b64uDecStrict(s) {              // canonica: respinge padding, alfabeti
  if (typeof s !== "string" || s.length % 4 === 1) throw 0;
  let bits = 0, nbits = 0; const bytes = [];
  for (const ch of s) { const v = A64.indexOf(ch); if (v < 0) throw 0;
    bits = (bits << 6) | v; nbits += 6;
    if (nbits >= 8) { nbits -= 8; bytes.push((bits >> nbits) & 0xff); } }
  if ((bits & ((1 << nbits) - 1)) !== 0) throw 0;   // bit di coda non zero
  const b = new Uint8Array(bytes);
  if (b64uEncPure(b) !== s) throw 0;               // ...e coda non canonica
  return b;
}
function b32Dec16Strict(s) {
  if (typeof s !== "string" || s.length !== 26) throw 0;
  for (const ch of s) if (!C.ALPHA.includes(ch)) throw 0;
  let bits = 0n;
  for (const ch of s) bits = (bits << 5n) | BigInt(C.ALPHA.indexOf(ch));
  if ((bits & 3n) !== 0n) throw 0;       // i 2 bit di coda devono essere zero
  bits >>= 2n;
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) { out[i] = Number(bits & 0xffn); bits >>= 8n; }
  if (C.b32Enc16(out) !== s) throw 0;
  return out;
}
function jsonDepth(x) {
  if (Array.isArray(x)) return 1 + (x.length ? Math.max(...x.map(jsonDepth)) : 0);
  if (x && typeof x === "object") { const v = Object.values(x);
    return 1 + (v.length ? Math.max(...v.map(jsonDepth)) : 0); }
  return 0;
}
const adMaster = (vaultId) => C.jcs({ d: "lockit/ad/master/v1", v: 1, vault_id: vaultId });

// -------- parseStructural({prefisso, dimensioneTotale}) : passi 0b..12 --------
export function parseStructural({ prefisso, dimensioneTotale }, opts = {}) {
  const bytes = prefisso; const total = dimensioneTotale;
  if (total >= 6 && bytes.length >= 6 &&
      new TextDecoder().decode(bytes.subarray(0, 4)) === "LKT1") {
    const ver = (bytes[4] << 8) | bytes[5];
    if (ver > 1) return { errore: "VERSIONE_FUTURA_NON_AUTENTICATA", rule: "0b" };
  }
  if (total < 6) return { errore: "MALFORMATO", rule: 1 };
  if (total < 9) return { errore: "MALFORMATO", rule: 2 };
  if (new TextDecoder().decode(bytes.subarray(0, 4)) !== "LKT1") return { errore: "NON_LOCKIT", rule: 3 };
  const ver = (bytes[4] << 8) | bytes[5];
  if (ver === 0) return { errore: "MALFORMATO", rule: 4 };
  const hl = (bytes[6] << 16) | (bytes[7] << 8) | bytes[8];
  if (hl > C.HDR_MAX) return { errore: "MALFORMATO", rule: 5 };
  if (9 + hl > total) return { errore: "MALFORMATO", rule: 5 };
  const hRaw = bytes.subarray(9, 9 + hl);       // il budget garantisce che ci sia
  let s;
  try { s = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(hRaw); }
  catch { return { errore: "MALFORMATO", rule: 6 }; }
  if (s.charCodeAt(0) === 0xfeff) return { errore: "MALFORMATO", rule: 6 };
  let obj;
  try { obj = JSON.parse(s); } catch { return { errore: "MALFORMATO", rule: 6 }; }
  const okStr = (str) => { for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const d = str.charCodeAt(i + 1); if (!(d >= 0xdc00 && d <= 0xdfff)) return false; i++; }
    else if (c >= 0xdc00 && c <= 0xdfff) return false; } return true; };
  const senzaSurr = (x) => { if (typeof x === "string") return okStr(x);
    if (x && typeof x === "object") { if (!Array.isArray(x)) for (const k of Object.keys(x)) if (!okStr(k)) return false;
      for (const w of (Array.isArray(x) ? x : Object.values(x))) if (!senzaSurr(w)) return false; } return true; };
  if (!senzaSurr(obj)) return { errore: "MALFORMATO", rule: 6 };
  try {
    if (jsonDepth(obj) > 8) return { errore: "MALFORMATO", rule: 6 };
    if (C.jcsStr(obj) !== s) return { errore: "MALFORMATO", rule: 6 };
  } catch { return { errore: "MALFORMATO", rule: 6 }; }
  const v = obj.v;
  if (typeof v === "number" && Number.isInteger(v) && v > 1) return { errore: "VERSIONE_FUTURA_NON_AUTENTICATA", rule: 7 };
  if (!(typeof v === "number" && Number.isInteger(v) && v === 1)) return { errore: "MALFORMATO", rule: 7 };
  if (opts.soloPrelettura) return { preOk: true };   // prelettura = ESATTAMENTE i passi 5-7
  if (obj.tipo !== "servizio") return { errore: "NON_SERVIZIO", rule: 8 };
  if (total > SIZE_MAX) return { errore: "MALFORMATO", rule: 9 };
  const keysEq = (o, ks) => o && typeof o === "object" && !Array.isArray(o) &&
    Object.keys(o).sort().join(",") === ks.slice().sort().join(",");
  let saltB, nonceB, ctB, macB;
  try {
    if (!keysEq(obj, ["epoch", "mac", "master", "tipo", "v", "vault_id"])) throw 0;
    if (!keysEq(obj.master, ["pw", "vault_id"])) throw 0;
    if (!keysEq(obj.master.pw, ["alg", "ct", "mem", "nonce", "ops", "salt"])) throw 0;
    if (obj.master.pw.alg !== "ARGON2ID13") throw 0;
    saltB = b64uDecStrict(obj.master.pw.salt); if (saltB.length !== 16) throw 0;
    nonceB = b64uDecStrict(obj.master.pw.nonce); if (nonceB.length !== 24) throw 0;
    ctB = b64uDecStrict(obj.master.pw.ct); if (ctB.length !== 48) throw 0;
    macB = b64uDecStrict(obj.mac); if (macB.length !== 32) throw 0;
    b32Dec16Strict(obj.vault_id); b32Dec16Strict(obj.master.vault_id);
    if (obj.vault_id !== obj.master.vault_id) throw 0;
    if (!(Number.isInteger(obj.epoch) && obj.epoch >= 1 && obj.epoch <= C.INT_MAX)) throw 0;
  } catch { return { errore: "MALFORMATO", rule: 9 }; }
  if (total !== 9 + hl) return { errore: "MALFORMATO", rule: 10 };  // corpo per differenza
  const { ops, mem } = obj.master.pw;
  if (!(Number.isInteger(ops) && ops >= 2 && ops <= 6)) return { errore: "MALFORMATO", rule: 11 };
  if (!(Number.isInteger(mem) && mem % 1024 === 0 && mem >= 67108864 && mem <= 268435456)) return { errore: "MALFORMATO", rule: 11 };
  const hNoMac = { ...obj }; delete hNoMac.mac;
  return { obj, hNoMacStr: C.jcsStr(hNoMac), saltB, nonceB, ctB, macB, ops, mem,
           epoch: obj.epoch, vaultId: obj.vault_id };
}

// -------- autentica(struct, kek) : SOLO passo 14 (H2) --------
export async function autentica(struct, kek) {
  await C.init();
  let vk;
  try {
    vk = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, struct.ctB, adMaster(struct.vaultId), struct.nonceB, kek);
  } catch { return { errore: "NON_AUTENTICO", rule: 14 }; }
  const kSvc = await C.hkdfSha256(vk, C.FORMAT_HKDF_SALT, te("lockit/svc/v1"));
  const atteso = await C.credAuth(kSvc, te(struct.hNoMacStr));
  if (!C.eq(atteso, struct.macB)) return { errore: "NON_AUTENTICO", rule: 14 };
  return { esito: "AUTENTICO", epoch: struct.epoch, vaultKey: vk };
}

// -------- buildService (C4, H1): salt, ops, mem SEMPRE obbligatori --------
export async function buildService({ vaultKey, vaultId, kekPw, password, salt, ops, mem, epoch, sorgenteNonce }) {
  await C.init();
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new Error("salt obbligatorio (16 byte)");
  if (!(Number.isInteger(ops) && Number.isInteger(mem))) throw new Error("ops e mem obbligatori");
  const kek = kekPw ?? await C.kekFromPassword(password, salt, ops, mem);
  const nonce = sorgenteNonce();
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(vaultKey, adMaster(vaultId), null, nonce, kek);
  const hNoMac = { epoch, master: { pw: { alg: "ARGON2ID13", ct: C.b64u(ct), mem, nonce: C.b64u(nonce), ops, salt: C.b64u(salt) }, vault_id: vaultId }, tipo: "servizio", v: 1, vault_id: vaultId };
  const kSvc = await C.hkdfSha256(vaultKey, C.FORMAT_HKDF_SALT, te("lockit/svc/v1"));
  const mac = await C.credAuth(kSvc, C.jcs(hNoMac));
  return C.buildFile("LKT1", { ...hNoMac, mac: C.b64u(mac) }, new Uint8Array(0));
}
